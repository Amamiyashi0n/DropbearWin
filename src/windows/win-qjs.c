/* Embedded QuickJS-ng (ES2023) runtime for Dropbear-win. */
#include "includes.h"
#ifdef DROPBEAR_WIN32_NATIVE
#include "win32-compat.h"
#include <io.h>
#include <fcntl.h>
#include "quickjs.h"
#include "quickjs-libc.h"

static const char DB_PRELUDE[] =
"import * as std from 'qjs:std';\n"
"import * as os from 'qjs:os';\n"
"globalThis.std = std;\n"
"globalThis.os = os;\n"
"const _b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';\n"
"const _b64rev = new Uint8Array(128).fill(255);\n"
"for (let i = 0; i < 64; i++) _b64rev[_b64.charCodeAt(i)] = i;\n"
"function _toUtf8Bytes(str) {\n"
"  const out = [];\n"
"  for (let i = 0; i < str.length; i++) {\n"
"    let c = str.charCodeAt(i);\n"
"    if (c < 0x80) out.push(c);\n"
"    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));\n"
"    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {\n"
"      const c2 = str.charCodeAt(++i);\n"
"      const cp = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);\n"
"      out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));\n"
"    } else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));\n"
"  }\n"
"  return new Uint8Array(out);\n"
"}\n"
"globalThis.db = {\n"
"  get args() { return globalThis.scriptArgs ? globalThis.scriptArgs.slice(1) : []; },\n"
"  get env() { return std.getenviron(); },\n"
"  cwd() { const [d, err] = os.getcwd(); if (err) throw new Error('getcwd failed: ' + err); return d; },\n"
"  readText(p) { const s = std.loadFile(p); if (s === null) throw new Error('Cannot read file: ' + p); return s; },\n"
"  writeText(p, text) { const f = std.open(p, 'wb'); if (!f) throw new Error('Cannot write file: ' + p); f.puts(String(text)); f.close(); },\n"
"  appendText(p, text) { const f = std.open(p, 'ab'); if (!f) throw new Error('Cannot append file: ' + p); f.puts(String(text)); f.close(); },\n"
"  readBytes(p) {\n"
"    const f = std.open(p, 'rb'); if (!f) throw new Error('Cannot read file: ' + p);\n"
"    f.seek(0, std.SEEK_END); const n = f.tell(); f.seek(0, std.SEEK_SET);\n"
"    const buf = new ArrayBuffer(n); if (n > 0) f.read(buf, 0, n); f.close(); return new Uint8Array(buf);\n"
"  },\n"
"  writeBytes(p, bytes) {\n"
"    const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);\n"
"    const f = std.open(p, 'wb'); if (!f) throw new Error('Cannot write file: ' + p);\n"
"    if (u.byteLength > 0) f.write(u.buffer, u.byteOffset, u.byteLength); f.close();\n"
"  },\n"
"  readJson(p) { return JSON.parse(globalThis.db.readText(p)); },\n"
"  writeJson(p, v, indent = 2) { globalThis.db.writeText(p, JSON.stringify(v, null, indent) + '\\n'); },\n"
"  readStdin() { return std.in.readAsString(); },\n"
"  b64encode(input) {\n"
"    const u = typeof input === 'string' ? _toUtf8Bytes(input) : (input instanceof Uint8Array ? input : new Uint8Array(input));\n"
"    let res = '';\n"
"    for (let i = 0; i < u.length; i += 3) {\n"
"      const a = u[i], b = i + 1 < u.length ? u[i + 1] : 0, c = i + 2 < u.length ? u[i + 2] : 0;\n"
"      res += _b64[a >> 2] + _b64[((a & 3) << 4) | (b >> 4)] +\n"
"        (i + 1 < u.length ? _b64[((b & 15) << 2) | (c >> 6)] : '=') +\n"
"        (i + 2 < u.length ? _b64[c & 63] : '=');\n"
"    }\n"
"    return res;\n"
"  },\n"
"  b64decode(str) {\n"
"    const clean = String(str).replace(/\\s+/g, '');\n"
"    const out = [];\n"
"    for (let i = 0; i < clean.length; i += 4) {\n"
"      const a = _b64rev[clean.charCodeAt(i)], b = _b64rev[clean.charCodeAt(i + 1)];\n"
"      const c = clean[i + 2] === '=' ? 64 : _b64rev[clean.charCodeAt(i + 2)];\n"
"      const d = clean[i + 3] === '=' ? 64 : _b64rev[clean.charCodeAt(i + 3)];\n"
"      if (a > 63 || b > 63 || c > 64 || d > 64) throw new Error('Invalid base64');\n"
"      out.push((a << 2) | (b >> 4));\n"
"      if (c < 64) out.push(((b & 15) << 4) | (c >> 2));\n"
"      if (d < 64) out.push(((c & 3) << 6) | d);\n"
"    }\n"
"    return new Uint8Array(out);\n"
"  }\n"
"};\n";

static int eval_buf(JSContext *ctx, const char *buf, size_t buf_len,
		const char *filename, int eval_flags) {
	JSValue val;
	int ret = 0;
	if ((eval_flags & JS_EVAL_TYPE_MASK) == JS_EVAL_TYPE_MODULE) {
		val = JS_Eval(ctx, buf, buf_len, filename, eval_flags | JS_EVAL_FLAG_COMPILE_ONLY);
		if (!JS_IsException(val)) {
			js_module_set_import_meta(ctx, val, 1, 1);
			val = JS_EvalFunction(ctx, val);
		}
		val = js_std_await(ctx, val);
	} else {
		val = JS_Eval(ctx, buf, buf_len, filename, eval_flags);
	}
	if (JS_IsException(val)) {
		js_std_dump_error(ctx);
		ret = 1;
	}
	JS_FreeValue(ctx, val);
	return ret;
}

static char *read_all_stdin(size_t *len_out) {
	size_t cap = 8192, used = 0;
	char *buf = malloc(cap);
	if (!buf) return NULL;
	for (;;) {
		size_t n;
		if (used + 4096 + 1 > cap) {
			char *grown;
			if (cap >= 16 * 1024 * 1024) { free(buf); return NULL; }
			cap *= 2;
			grown = realloc(buf, cap);
			if (!grown) { free(buf); return NULL; }
			buf = grown;
		}
		n = fread(buf + used, 1, 4096, stdin);
		used += n;
		if (n < 4096) break;
	}
	buf[used] = '\0';
	*len_out = used;
	return buf;
}

static void print_qjs_usage(FILE *stream) {
	fputs(
		"Usage: qjs [options] [file.js | -] [args...]\n"
		"  -e, --eval <code>    Evaluate JavaScript code\n"
		"  -m, --module         Force ES module mode\n"
		"  -                    Read JavaScript from stdin\n"
		"  -v, --version        Show QuickJS-ng version\n"
		"  -h, --help           Show this help\n"
		"\nGlobals: std (qjs:std), os (qjs:os), db (readText/writeText/appendText/\n"
		"readBytes/writeBytes/readJson/writeJson/readStdin/b64encode/b64decode/args/env/cwd)\n",
		stream);
}

int dropbear_win_qjs_main(int argc, char **argv) {
	JSRuntime *rt = NULL;
	JSContext *ctx = NULL;
	const char *eval_code = NULL;
	const char *filename = NULL;
	int force_module = 0;
	int read_stdin = 0;
	int i = 1;
	int status = 0;

	while (i < argc) {
		const char *arg = argv[i];
		if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
			print_qjs_usage(stdout);
			return 0;
		}
		if (!strcmp(arg, "-v") || !strcmp(arg, "--version")) {
			printf("quickjs-ng %s (Dropbear-win embedded)\n", JS_GetVersion());
			return 0;
		}
		if (!strcmp(arg, "-m") || !strcmp(arg, "--module")) {
			force_module = 1;
			i++;
			continue;
		}
		if (!strcmp(arg, "-e") || !strcmp(arg, "--eval")) {
			if (i + 1 >= argc) {
				fputs("qjs: -e requires an argument\n", stderr);
				return 2;
			}
			eval_code = argv[i + 1];
			i += 2;
			break;
		}
		if (!strcmp(arg, "--")) {
			i++;
			break;
		}
		if (!strcmp(arg, "-")) {
			read_stdin = 1;
			i++;
			break;
		}
		if (arg[0] == '-') {
			fprintf(stderr, "qjs: unknown option: %s\n", arg);
			return 2;
		}
		filename = arg;
		i++;
		break;
	}

	if (!eval_code && !filename && !read_stdin) {
		if (i < argc) {
			if (!strcmp(argv[i], "-")) read_stdin = 1;
			else filename = argv[i];
			i++;
		} else {
			print_qjs_usage(stderr);
			return 2;
		}
	}

	rt = JS_NewRuntime();
	if (!rt) {
		fputs("qjs: failed to create runtime\n", stderr);
		return 1;
	}
	js_std_set_worker_new_context_func(NULL);
	js_std_init_handlers(rt);
	JS_SetModuleLoaderFunc2(rt, NULL, js_module_loader, js_module_check_attributes, NULL);

	ctx = JS_NewContext(rt);
	if (!ctx) {
		fputs("qjs: failed to create context\n", stderr);
		js_std_free_handlers(rt);
		JS_FreeRuntime(rt);
		return 1;
	}

	js_init_module_std(ctx, "qjs:std");
	js_init_module_os(ctx, "qjs:os");
	{
		/* Build scriptArgs: [script_name, remaining args...] */
		int script_argc = (argc - i) + 1;
		char **script_argv = calloc((size_t)script_argc + 1, sizeof(char *));
		if (!script_argv) { status = 1; goto done; }
		script_argv[0] = (char *)(filename ? filename : (eval_code ? "<eval>" : "<stdin>"));
		for (int k = 0; k < argc - i; k++) script_argv[k + 1] = argv[i + k];
		js_std_add_helpers(ctx, script_argc, script_argv);
		free(script_argv);
	}

	/* Load built-in std/os/db globals via ES module prelude. */
	if (eval_buf(ctx, DB_PRELUDE, sizeof(DB_PRELUDE) - 1, "<dropbear-prelude>", JS_EVAL_TYPE_MODULE)) {
		status = 1;
		goto done;
	}

	if (eval_code) {
		int flags = force_module ? JS_EVAL_TYPE_MODULE : JS_EVAL_TYPE_GLOBAL;
		status = eval_buf(ctx, eval_code, strlen(eval_code), "<eval>", flags);
	} else if (read_stdin) {
		size_t len = 0;
		char *src = read_all_stdin(&len);
		if (!src) {
			fputs("qjs: failed to read stdin\n", stderr);
			status = 1;
		} else {
			int is_mod = force_module || JS_DetectModule(src, len);
			status = eval_buf(ctx, src, len, "<stdin>", is_mod ? JS_EVAL_TYPE_MODULE : JS_EVAL_TYPE_GLOBAL);
			free(src);
		}
	} else {
		size_t len = 0;
		uint8_t *buf = js_load_file(ctx, &len, filename);
		if (!buf) {
			fprintf(stderr, "qjs: cannot load file: %s\n", filename);
			status = 1;
		} else {
			int is_mod = force_module || JS_DetectModule((const char *)buf, len);
			status = eval_buf(ctx, (const char *)buf, len, filename,
				is_mod ? JS_EVAL_TYPE_MODULE : JS_EVAL_TYPE_GLOBAL);
			js_free(ctx, buf);
		}
	}

	if (status == 0) {
		if (js_std_loop(ctx) < 0) {
			js_std_dump_error(ctx);
			status = 1;
		}
	}

done:
	js_std_free_handlers(rt);
	JS_FreeContext(ctx);
	JS_FreeRuntime(rt);
	return status;
}

/* Match direct SSH exec commands like `qjs -e "..."`, `qjs script.js`, `qjs -`
 * when no unquoted CMD shell operators are present. */
int dropbear_win_is_qjs_command(const char *command) {
	const char *p;
	char quote = 0;
	if (!command) return 0;
	if (strlen(command) > 15000) return 0;
	p = command;
	while (*p == ' ' || *p == '\t') p++;
	if (strncmp(p, "qjs", 3) != 0) return 0;
	if (p[3] != '\0' && p[3] != ' ' && p[3] != '\t') return 0;
	for (; *p; p++) {
		char c = *p;
		if (c == '\r' || c == '\n') return 0;
		if (quote) {
			if (c == '\\' && quote == '"' && p[1]) { p++; continue; }
			if (c == quote) quote = 0;
			continue;
		}
		if (c == '"' || c == '\'') { quote = c; continue; }
		if (c == '&' || c == '|' || c == '<' || c == '>' || c == '%' || c == '^') return 0;
	}
	return quote == 0;
}

int dropbear_win_qjs_exec_command(const char *command) {
	size_t len = strlen(command);
	char *copy = malloc(len + 1);
	char **argv = calloc(len / 2 + 4, sizeof(char *));
	int argc = 0;
	const char *src = command;
	char *dst;
	int result;

	if (!copy || !argv) {
		free(copy);
		free(argv);
		return 1;
	}
	dst = copy;
	while (*src) {
		char quote = 0;
		while (*src == ' ' || *src == '\t') src++;
		if (!*src) break;
		argv[argc++] = dst;
		while (*src) {
			if (quote) {
				if (quote == '"' && *src == '\\' && (src[1] == '"' || src[1] == '\\')) {
					src++;
					*dst++ = *src++;
					continue;
				}
				if (*src == quote) { quote = 0; src++; continue; }
				*dst++ = *src++;
				continue;
			}
			if (*src == ' ' || *src == '\t') break;
			if (*src == '"' || *src == '\'') { quote = *src++; continue; }
			*dst++ = *src++;
		}
		*dst++ = '\0';
	}
	argv[argc] = NULL;
	result = dropbear_win_qjs_main(argc, argv);
	free(argv);
	free(copy);
	return result;
}
#endif
