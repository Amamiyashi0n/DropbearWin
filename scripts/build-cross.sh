#!/usr/bin/env bash
# Cross-compile the native Windows server from a Linux host with MinGW-w64.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/build-cross.sh [--architecture all|x64|x86] [--clean] [--jobs N]

Requires Bash, make, Python 3, and the x86_64-w64-mingw32 and/or
i686-w64-mingw32 GCC and binutils toolchains. The default builds both targets.
EOF
}

architecture=all
clean=0
jobs=6
while (($#)); do
    case "$1" in
        --architecture)
            (($# >= 2)) || { usage >&2; exit 2; }
            architecture=$2
            shift 2
            ;;
        --clean)
            clean=1
            shift
            ;;
        --jobs)
            (($# >= 2)) || { usage >&2; exit 2; }
            jobs=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
done
case "$architecture" in all|x64|x86) ;; *) usage >&2; exit 2 ;; esac
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || { printf 'Invalid job count: %s\n' "$jobs" >&2; exit 2; }

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
source_dir=$project_root/vendor/dropbear
build_root=$project_root/build
dist_dir=$project_root/dist
build_host=$(sh "$source_dir/src/config.guess")

for command_name in make python3 sha256sum; do
    command -v "$command_name" >/dev/null || { printf 'Missing command: %s\n' "$command_name" >&2; exit 1; }
done
[[ -f "$source_dir/configure" ]] || { printf 'Missing Dropbear configure script\n' >&2; exit 1; }

if [[ "$architecture" == all ]]; then
    targets=(x64 x86)
else
    targets=("$architecture")
fi

mkdir -p "$build_root" "$dist_dir"
stage_dir=$(mktemp -d "$build_root/.cross-stage.XXXXXX")
trap 'rm -rf "$stage_dir"' EXIT

show_failure() {
    local log=$1
    printf 'Build failed. Last output from %s:\n' "$log" >&2
    if grep -Eq 'error:|undefined reference|Error [0-9]|Permission denied' "$log"; then
        grep -E -B 2 -A 2 'error:|undefined reference|Error [0-9]|Permission denied' "$log" \
            | tail -n 80 | cut -c 1-300 >&2
    else
        tail -n 40 "$log" | cut -c 1-300 >&2
    fi
}

assert_pe_compatibility() {
    local arch=$1 executable=$2 objdump=$3 expected_format=$4 major=$5 minor=$6
    local info dll forbidden
    info=$("$objdump" -p "$executable") || return 1
    grep -Fq "file format $expected_format" <<<"$info" || {
        printf '%s: expected %s PE format\n' "$executable" "$expected_format" >&2
        return 1
    }
    grep -Eq "MajorSubsystemVersion[[:space:]]+$major([[:space:]]|$)" <<<"$info" || return 1
    grep -Eq "MinorSubsystemVersion[[:space:]]+$minor([[:space:]]|$)" <<<"$info" || return 1
    grep -aFq 'requireAdministrator' "$executable" || {
        printf '%s: missing administrator request manifest\n' "$arch" >&2
        return 1
    }

    while IFS= read -r dll; do
        case "${dll,,}" in
            advapi32.dll|kernel32.dll|msvcrt.dll|ws2_32.dll) ;;
            *) printf '%s: unexpected DLL import: %s\n' "$arch" "$dll" >&2; return 1 ;;
        esac
    done < <(sed -n 's/^[[:space:]]*DLL Name:[[:space:]]*//p' <<<"$info")

    for forbidden in InitOnceExecuteOnce _putenv_s BCrypt CreatePseudoConsole \
        InitializeProcThreadAttributeList UpdateProcThreadAttribute \
        GetSystemTimePreciseAsFileTime GetTickCount64 CancelIoEx \
        WTSGetActiveConsoleSessionId; do
        if grep -Fq "$forbidden" <<<"$info"; then
            printf '%s: unsupported API import: %s\n' "$arch" "$forbidden" >&2
            return 1
        fi
    done
}

build_target() {
    local arch=$1 triplet nt major minor format output_name
    if [[ "$arch" == x64 ]]; then
        triplet=x86_64-w64-mingw32
        nt=0x0502
        major=5
        minor=2
        format=pei-x86-64
    else
        triplet=i686-w64-mingw32
        nt=0x0501
        major=5
        minor=1
        format=pei-i386
    fi
    output_name=dropbear-win-$arch.exe
    local tool
    for tool in gcc ar ranlib strip objdump windres; do
        command -v "$triplet-$tool" >/dev/null || {
            printf 'Missing cross tool: %s-%s\n' "$triplet" "$tool" >&2
            return 1
        }
    done
    if ! printf 'int main(void) { return 0; }\n' \
        | "$triplet-gcc" -mcrtdll=msvcrt-os -x c -fsyntax-only - >/dev/null 2>&1; then
        printf '%s-gcc must support -mcrtdll=msvcrt-os for the Windows compatibility target\n' \
            "$triplet" >&2
        return 1
    fi

    local build_dir=$build_root/$arch
    if ((clean)); then rm -rf -- "$build_dir"; fi
    mkdir -p "$build_dir"
    mkdir -p "$build_dir/obj"
    local manifest_resource=$build_dir/obj/dropbear-win-manifest.o
    "$triplet-windres" -I "$project_root/src/windows" -i "$project_root/src/windows/dropbear-win.rc" \
        -o "$manifest_resource" -O coff
    # libtommath inherits CFLAGS but not the parent Makefile's CPPFLAGS.
    # Keep the Windows options here as well, so every bundled library sees them.
    # Some Linux MinGW distributions route libmsvcrt.a to UCRT. The OS CRT
    # variant is required for XP/Server 2003 and must be selected at both
    # compile and link time.
    local crtflag=-mcrtdll=msvcrt-os
    local cflags="-O2 -fno-ident -ffunction-sections -fdata-sections -w $crtflag -I$source_dir/src -I$build_dir -DDISTROOPTIONS_H_EXISTS -DDROPBEAR_WIN32_NATIVE -DFD_SETSIZE=1024 -D_WIN32_WINNT=$nt -DWINVER=$nt"
    local cppflags="$crtflag -DDISTROOPTIONS_H_EXISTS -DDROPBEAR_WIN32_NATIVE -DFD_SETSIZE=1024 -D_WIN32_WINNT=$nt -DWINVER=$nt -include winsock2.h -include ws2tcpip.h"
    local ldflags="$crtflag -static -static-libgcc -Wl,--gc-sections -Wl,--major-os-version,$major,--minor-os-version,$minor -Wl,--major-subsystem-version,$major,--minor-subsystem-version,$minor"

    printf 'Cross-compiling %s with %s-gcc\n' "$arch" "$triplet"
    if ! (cd "$build_dir" && env \
        CC="$triplet-gcc" AR="$triplet-ar" RANLIB="$triplet-ranlib" STRIP="$triplet-strip" \
        ac_cv_c_undeclared_builtin_options='none needed' \
        ac_cv_type_socklen_t=yes \
        ac_cv_type_struct_sockaddr_storage=yes \
        ac_cv_have_struct_sockaddr_storage=yes \
        ac_cv_have_struct_sockaddr_in6=yes \
        ac_cv_have_struct_in6_addr=yes \
        ac_cv_have_struct_addrinfo=yes \
        ac_cv_func_getaddrinfo=yes ac_cv_func_freeaddrinfo=yes ac_cv_func_getnameinfo=yes \
        CPPFLAGS="$cppflags" CFLAGS="$cflags" LDFLAGS="$ldflags" \
        LIBS='-lws2_32 -ladvapi32' \
        sh "$source_dir/configure" \
            --build="$build_host" --host="$triplet" \
            --enable-static --enable-bundled-libtom --disable-harden \
            --disable-zlib --disable-pam --disable-openpty --disable-syslog \
            --disable-lastlog --disable-utmp --disable-utmpx \
            --disable-wtmp --disable-wtmpx --disable-loginfunc \
            --disable-pututline --disable-pututxline \
        > configure-output.log 2>&1); then
        show_failure "$build_dir/configure-output.log"
        return 1
    fi
    if ! make -C "$build_dir" -j"$jobs" \
        PROGRAMS='dropbear scp' MULTI=1 STATIC=1 \
        WIN_RESOURCE="$manifest_resource" \
        CFLAGS="$cflags" LDFLAGS="$ldflags" \
        > "$build_dir/build-output.log" 2>&1; then
        show_failure "$build_dir/build-output.log"
        return 1
    fi

    local staged=$stage_dir/$output_name
    cp -- "$build_dir/dropbearmulti.exe" "$staged"
    "$triplet-strip" -s "$staged"
    assert_pe_compatibility "$arch" "$staged" "$triplet-objdump" "$format" "$major" "$minor"
    printf 'Built %-3s: %s bytes, SHA-256 %s\n' "$arch" \
        "$(stat -c '%s' "$staged")" "$(sha256sum "$staged" | cut -d ' ' -f 1)"
}

for target in "${targets[@]}"; do build_target "$target"; done

python3 - "$stage_dir" "$stage_dir/build-manifest.json" "${targets[@]}" <<'PY'
import datetime
import hashlib
import json
import pathlib
import sys

stage = pathlib.Path(sys.argv[1])
manifest = pathlib.Path(sys.argv[2])
artifacts = []
for architecture in sys.argv[3:]:
    filename = f"dropbear-win-{architecture}.exe"
    data = (stage / filename).read_bytes()
    artifacts.append({
        "file": filename,
        "architecture": architecture,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest().upper(),
        "minimumNt": "5.2" if architecture == "x64" else "5.1",
    })
manifest.write_text(json.dumps({
    "builtAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
    "artifacts": artifacts,
}, indent=2) + "\n", encoding="utf-8")
PY

for target in "${targets[@]}"; do
    cp -- "$stage_dir/dropbear-win-$target.exe" "$dist_dir/dropbear-win-$target.exe"
done
mv -- "$stage_dir/build-manifest.json" "$dist_dir/build-manifest.json"
printf 'Release files: %s\n' "$dist_dir"
