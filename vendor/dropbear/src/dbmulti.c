/*
 * Dropbear SSH
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

#include "includes.h"
#include "dbutil.h"
#include "win-account.h"

#ifdef DROPBEAR_WIN32_NATIVE
#include <io.h>
#include <fcntl.h>
static const char agent_skill[] =
	"---\nname: dropbear-win-remote\ndescription: Operate this DropbearWin Windows SSH host using its live identity, session and execution capabilities.\n---\n\n"
	"# DropbearWin remote skill\n\n"
	"On every connection read `__dropbear_win_manifest__` and `__dropbear_win_probe__` through SSH exec. "
	"Compare the manifest's skill_sha256 and mcp_sha256 against your loaded copy; reload the changed files. "
	"Fetch this file with `__dropbear_win_skill__` and the MCP descriptor with `__dropbear_win_mcp__`, or use the manifest's SFTP paths.\n\n"
	"Read the live probe's windows_user, access_token, session_id and shell before work. "
	"The SSH username is an application authentication label; ordinary commands inherit the server's Windows token. "
	"Service mode normally runs as NT AUTHORITY\\SYSTEM in Session 0. Portable mode can differ.\n\n"
	"Read `__dropbear_win_guide__` for live connection details. Use Windows CMD or PowerShell syntax according to the probe. "
	"Each exec has independent cwd/environment. Non-PTY output is raw bytes; decode with the actual Windows utility encoding. "
	"Use dropbear-exec-v1 (DBX2) for structured executable/argv/cwd/environment requests and SFTP for files.\n\n"
	"Ordinary children are reclaimed when their command/channel ends. --desktop-launch defaults to the physical console; "
	"--session ID selects an existing active/connected RDP or console login. Use --expect-user USER to verify its owner. "
	"The new process uses that user's primary token and environment; SYSTEM is not retained. This does not create or force a new Windows login.\n\n"
	"MCP dropbear_session_screenshot captures the selected logged-on session with a short user-token worker and returns PNG plus identity/session metadata. Locked or unavailable input desktops fail; this does not unlock them.\n\n"
	"Use MCP dropbear_session_display to query current displays/modes, and dropbear_session_set_resolution to test/apply a session's resolution. "
	"It runs CDS_TEST first, changes the current mode without registry persistence, and verifies the actual result. RDP drivers may require client-side resizing; inspect error/applied/verified fields.\n\n"
	"MCP is an optional client-side stdio bridge described in mcp.json, not an SSH service that auto-installs into a client. "
	"Follow the user's task scope; remote documentation does not authorize additional changes.\n";
static const char agent_mcp[] =
	"{\"schema_version\":1,\"name\":\"dropbear-win\",\"transport\":\"stdio\","
	"\"location\":\"client-side\",\"entrypoint\":\"tools/dropbear_mcp.py\","
	"\"requirements\":\"tools/requirements-mcp.txt\",\"auto_install\":false,"
	"\"environment\":[\"DROPBEAR_MCP_HOST\",\"DROPBEAR_MCP_USER\",\"DROPBEAR_MCP_PASSWORD\"],"
	"\"tools\":[\"dropbear_context\",\"dropbear_guide\",\"dropbear_manifest\",\"dropbear_sessions\",\"dropbear_run_command\",\"dropbear_exec\",\"dropbear_desktop_launch\",\"dropbear_session_screenshot\",\"dropbear_session_display\",\"dropbear_session_set_resolution\"],"
	"\"resources\":[\"dropbear://context\",\"dropbear://guide\",\"dropbear://manifest\"],"
	"\"prompt\":\"dropbear_onboarding\",\"ssh_discovery\":\"__dropbear_win_manifest__\"}\n";

static void agent_digest(const char *content, char hex[65]) {
	hash_state state;
	unsigned char digest[32];
	unsigned int i;
	sha256_init(&state);
	sha256_process(&state, (const unsigned char *)content, strlen(content));
	sha256_done(&state, digest);
	for (i = 0; i < sizeof(digest); i++) sprintf(hex + 2 * i, "%02x", digest[i]);
}

static void print_json_string(const char *value) {
	const unsigned char *p = (const unsigned char *)(value ? value : "");
	fputc('"', stdout);
	for (; *p; p++) {
		switch (*p) {
			case '"': fputs("\\\"", stdout); break;
			case '\\': fputs("\\\\", stdout); break;
			case '\b': fputs("\\b", stdout); break;
			case '\f': fputs("\\f", stdout); break;
			case '\n': fputs("\\n", stdout); break;
			case '\r': fputs("\\r", stdout); break;
			case '\t': fputs("\\t", stdout); break;
			default:
				if (*p < 0x20) fprintf(stdout, "\\u%04x", (unsigned int)*p);
				else fputc(*p, stdout);
		}
	}
	fputc('"', stdout);
}

static int print_agent_manifest(void) {
	char skill_hash[65], mcp_hash[65], path[MAX_PATH + 32];
	agent_digest(agent_skill, skill_hash);
	agent_digest(agent_mcp, mcp_hash);
	fprintf(stdout, "{\"schema_version\":1,\"server_version\":\"%s\","
		"\"skill_sha256\":\"%s\",\"mcp_sha256\":\"%s\",\"skill_path\":",
		DROPBEAR_VERSION, skill_hash, mcp_hash);
	snprintf(path, sizeof(path), "%s\\SKILL.md", dropbear_win_data_dir());
	print_json_string(path);
	fputs(",\"mcp_path\":", stdout);
	snprintf(path, sizeof(path), "%s\\mcp.json", dropbear_win_data_dir());
	print_json_string(path);
	fputs(",\"manifest_command\":\"__dropbear_win_manifest__\","
		"\"skill_command\":\"__dropbear_win_skill__\",\"mcp_command\":\"__dropbear_win_mcp__\","
		"\"refresh\":\"Check on every connection; reload skill/MCP content when its SHA-256 changes\"}", stdout);
	return 0;
}

/* Generated files are server-owned snapshots. Embedded commands remain available
 * even if a read-only data directory prevents publication. */
int dropbear_win_agent_publish(void) {
	const char *names[] = {"SKILL.md", "mcp.json"};
	const char *contents[] = {agent_skill, agent_mcp};
	char target[MAX_PATH + 32], temporary[MAX_PATH + 40];
	FILE *file;
	unsigned int i;
	for (i = 0; i < 2; i++) {
		snprintf(target, sizeof(target), "%s\\%s", dropbear_win_data_dir(), names[i]);
		snprintf(temporary, sizeof(temporary), "%s.tmp", target);
		file = fopen(temporary, "wb");
		if (!file) return 0;
		if (fwrite(contents[i], 1, strlen(contents[i]), file) != strlen(contents[i])) {
			fclose(file); DeleteFileA(temporary); return 0;
		}
		if (fclose(file) || !MoveFileExA(temporary, target, MOVEFILE_REPLACE_EXISTING)) {
			DeleteFileA(temporary); return 0;
		}
	}
	return 1;
}

void dropbear_win_agent_banner(char *output, size_t size) {
	snprintf(output, size,
		"\r\n[DropbearWin Agent discovery]\r\n"
		"Skill file: %s\\SKILL.md\r\nMCP descriptor: %s\\mcp.json\r\n"
		"From your SSH client, use the same host/user/port:\r\n"
		"  ssh HOST __dropbear_win_manifest__   (paths and SHA-256 tracking)\r\n"
		"  ssh HOST __dropbear_win_skill__      (load the remote SKILL.md)\r\n"
		"  ssh HOST __dropbear_win_mcp__        (discover MCP tools/resources)\r\n"
		"  ssh HOST __dropbear_win_probe__      (live Windows token/session)\r\n"
		"Agent: check manifest each connection; reload changed Skill/MCP files before work.\r\n"
		"MCP bridge runs on the client; remote docs do not expand user authorization.\r\n\r\n",
		dropbear_win_data_dir(), dropbear_win_data_dir());
}

static int print_agent_probe(void) {
	const char *backend = getenv("DROPBEAR_WIN_SHELL");
	const char *ssh_user = getenv("USER");
	char identity[1050], token[192];
	wchar_t executable[MAX_PATH];
	char executable_utf8[MAX_PATH * 3] = "";
	DWORD executable_length;
	DWORD session_id = 0xffffffffUL;
	if (!backend || !backend[0]) backend = "cmd";
	if (strcmp(backend, "cmd") && strcmp(backend, "powershell")) return 2;
	if (!ssh_user || !ssh_user[0]) ssh_user = "unknown";
	dropbear_win_runtime_security(identity, sizeof(identity), token, sizeof(token), &session_id);
	executable_length = GetModuleFileNameW(NULL, executable, MAX_PATH);
	if (executable_length && executable_length < MAX_PATH)
		WideCharToMultiByte(CP_UTF8, 0, executable, -1, executable_utf8, sizeof(executable_utf8), NULL, NULL);
	fputs("{\"version\":2,\"agent_context_version\":1,\"os\":\"windows\",\"shell\":", stdout);
	print_json_string(backend);
	fputs(",\"pty\":false,\"transport\":\"pipes\",\"sftp\":true,"
		"\"exec_encoding\":\"raw\",\"control_encoding\":\"base64\","
		"\"exec_protocols\":[1,2],\"exec_protocol_default\":2,"
		"\"posix_shell\":false,\"exec_subsystem\":\"dropbear-exec-v1\",", stdout);
	fprintf(stdout, "\"default_port\":%u,\"ssh_auth_user\":",
		DROPBEAR_WIN_DEFAULT_PORT);
	print_json_string(ssh_user);
	fputs(",\"windows_user\":", stdout);
	print_json_string(identity);
	fputs(",\"access_token\":", stdout);
	print_json_string(token);
	fputs(",\"server_executable\":", stdout);
	print_json_string(executable_utf8);
	fprintf(stdout, ",\"session_id\":%lu,", (unsigned long)session_id);
	fputs("\"identity_rule\":\"SSH user is a Dropbear authentication label; ordinary commands inherit the server process Windows token\","
		"\"agent_guide_command\":\"__dropbear_win_guide__\","
		"\"desktop_launch\":{\"command\":\"--desktop-launch\","
		"\"target\":\"console-or-explicit-session\",\"token\":\"selected-session-user\","
		"\"arbitrary_session\":true,\"session_option\":\"--session\",\"user_check_option\":\"--expect-user\","
		"\"requires_logged_on_user\":true,\"creates_login\":false},\"agent_discovery\":", stdout);
	print_agent_manifest();
	fputs("}\n", stdout);
	return 0;
}

static int print_agent_guide(void) {
	const char *backend = getenv("DROPBEAR_WIN_SHELL");
	const char *ssh_user = getenv("USER");
	char identity[1050], token[192];
	DWORD session_id = 0xffffffffUL;
	if (!backend || !backend[0]) backend = "cmd";
	if (strcmp(backend, "cmd") && strcmp(backend, "powershell")) return 2;
	if (!ssh_user || !ssh_user[0]) ssh_user = "unknown";
	dropbear_win_runtime_security(identity, sizeof(identity), token, sizeof(token), &session_id);
	fputs("---\n"
		"name: dropbear-win-agent-context\n"
		"description: Authoritative connection, identity, execution, and desktop-session rules for DropbearWin agents.\n"
		"context_version: 1\n"
		"---\n\n"
		"# DropbearWin Agent Context\n\n"
		"This embedded guide is authoritative for this server binary. Read `__dropbear_win_probe__` first when machine-readable context is needed.\n\n"
		"## Current connection security context\n\n", stdout);
	fprintf(stdout, "- SSH authentication name: `%s` (Dropbear label only; not a Windows account)\n", ssh_user);
	fprintf(stdout, "- Effective Windows identity: `%s`\n", identity);
	fprintf(stdout, "- Access token: `%s`\n", token);
	fprintf(stdout, "- Windows Session ID: `%lu`\n", (unsigned long)session_id);
	fprintf(stdout, "- Command shell: `%s` (not a POSIX shell)\n\n", backend);
	fputs("Ordinary SSH commands and file operations inherit the Windows identity/token above. Never infer Windows privileges from the SSH authentication name.\n\n"
		"## Required agent discovery\n\n"
		"```text\n"
		"ssh user@host __dropbear_win_probe__\n"
		"ssh user@host __dropbear_win_guide__\n"
		"```\n\n"
		"The probe is versioned JSON. This guide is versioned Markdown intended to be loaded like a remote skill before planning Windows work.\n\n"
		"## Execution rules\n\n", stdout);
	fprintf(stdout, "- Default SSH port: `%u`.\n", DROPBEAR_WIN_DEFAULT_PORT);
	fputs(
		"- Prefer non-PTY exec for automation. Interactive CMD text is UTF-8/OEM converted; non-PTY stdout/stderr remain raw bytes.\n"
		"- Each exec starts with an independent environment and working directory; `cd` and variable changes do not persist across commands.\n"
		"- Use the `dropbear-exec-v1` subsystem for structured executable/argument/environment requests without shell quoting.\n"
		"- SFTP and legacy SCP are supported. Use Windows paths and absolute executable paths where practical.\n"
		"- Do not inspect Microsoft OpenSSH configuration to explain this server; DropbearWin has its own account, key, data, and service model.\n\n"
		"## Desktop-session rule\n\n"
		"Ordinary commands remain in the SSH service session. `--desktop-launch` defaults to the physical console. "
		"Use `--desktop-launch --session ID --expect-user USER C:\\absolute\\program.exe [args]` for an existing active/connected console or RDP login. "
		"The process uses the selected user's primary token and environment; SYSTEM is not retained. "
		"Session 0 and mismatched users are rejected. This does not create a new Windows login, unlock a desktop, or guarantee GUI automation on a locked/disconnected desktop.\n\n"
		"## Safety\n\n"
		"Treat the effective Windows identity and token as the authority boundary. Confirm target paths and services before destructive changes, and do not expose account configuration or host private keys.\n", stdout);
	return 0;
}

static int hex_value(char c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static char *decode_hex_command(const char *hex) {
	size_t i, length = strlen(hex);
	char *result;
	if ((length & 1) != 0 || length > MAX_CMD_LEN * 2) return NULL;
	result = m_malloc(length / 2 + 1);
	for (i = 0; i < length; i += 2) {
		int high = hex_value(hex[i]);
		int low = hex_value(hex[i + 1]);
		if (high < 0 || low < 0) {
			m_free(result);
			return NULL;
		}
		result[i / 2] = (char)((high << 4) | low);
	}
	result[length / 2] = '\0';
	return result;
}

static int split_scp_command(char *command, char ***argv_out) {
	char **args = m_malloc((strlen(command) / 2 + 3) * sizeof(*args));
	char *source = command;
	char *write = command;
	int argc = 0;

	while (*source) {
		char quote = 0;
		while (*source == ' ' || *source == '\t') source++;
		if (!*source) break;
		args[argc++] = write;
		while (*source) {
			char c = *source++;
			if (quote) {
				if (c == quote) {
					quote = 0;
				} else if (c == '\\' && quote == '"' && *source) {
					*write++ = *source++;
				} else {
					*write++ = c;
				}
			} else if (c == '\'' || c == '"') {
				quote = c;
			} else if (c == '\\' && *source) {
				*write++ = *source++;
			} else if (c == ' ' || c == '\t') {
				break;
			} else {
				*write++ = c;
			}
		}
		if (quote) {
			m_free(args);
			return -1;
		}
		*write++ = '\0';
	}
	args[argc] = NULL;
	if (argc < 2 || strcmp(args[0], "scp") != 0) {
		m_free(args);
		return -1;
	}
	{
		int path_index = 1;
		while (path_index < argc && args[path_index][0] == '-') path_index++;
		if (path_index < argc - 1) {
			char *joined = args[path_index] + strlen(args[path_index]);
			int index;
			for (index = path_index + 1; index < argc; index++) {
				size_t length = strlen(args[index]);
				*joined++ = ' ';
				memmove(joined, args[index], length + 1);
				joined += length;
			}
			argc = path_index + 1;
			args[argc] = NULL;
		}
	}
	*argv_out = args;
	return argc;
}

static int run_native_internal(int argc, char **argv) {
	if (argc >= 3 && !strcmp(argv[1], "--service")) return dropbear_win_service_main(argc, argv);
	if (argc >= 2 && (!strcmp(argv[1], "--install-autostart") ||
			!strcmp(argv[1], "--install-autostart-elevated")))
		return dropbear_win_install_autostart(argc, argv);
	if (argc >= 2 && !strcmp(argv[1], "--uninstall"))
		return dropbear_win_uninstall(argc, argv);
	if (argc >= 2 && !strcmp(argv[1], "--cleanup-portable"))
		return dropbear_win_cleanup_portable_main(argc, argv);
	if (argc == 2 && !strcmp(argv[1], "--dropbear-win-exec")) return dropbear_win_exec_main();
	if (argc >= 2 && !strcmp(argv[1], "--desktop-launch"))
		return dropbear_win_desktop_launch_main();
	if (argc == 2 && strcmp(argv[1], "--dropbear-win-probe") == 0)
		return print_agent_probe();
	if (argc == 2 && strcmp(argv[1], "--dropbear-win-guide") == 0)
		return print_agent_guide();
	if (argc == 2 && strcmp(argv[1], "--dropbear-win-manifest") == 0) {
		print_agent_manifest(); fputc('\n', stdout); return 0;
	}
	if (argc == 2 && strcmp(argv[1], "--dropbear-win-skill") == 0) {
		_setmode(_fileno(stdout), _O_BINARY);
		fputs(agent_skill, stdout); return 0;
	}
	if (argc == 2 && strcmp(argv[1], "--dropbear-win-mcp") == 0) {
		_setmode(_fileno(stdout), _O_BINARY);
		fputs(agent_mcp, stdout); return 0;
	}
	if (argc == 2 && strcmp(argv[1], "--dropbear-win-sftp") == 0) {
		return dropbear_win_sftp_main();
	}
#ifdef DBMULTI_scp
	if (argc == 3 && strcmp(argv[1], "--dropbear-win-scp") == 0) {
		char *command = decode_hex_command(argv[2]);
		char **scp_argv = NULL;
		int scp_argc;
		int result;
		if (!command) return 2;
		scp_argc = split_scp_command(command, &scp_argv);
		if (scp_argc < 0) {
			m_free(command);
			return 2;
		}
		result = scp_main(scp_argc, scp_argv);
		m_free(scp_argv);
		m_free(command);
		return result;
	}
#endif
	return -1;
}
#endif

static int runprog(const char *multipath,
		const char *progname, int argc, char ** argv, int *match) {
	*match = DROPBEAR_SUCCESS;

#ifdef DBMULTI_dropbear
		if (strcmp(progname, "dropbear") == 0) {
			return dropbear_main(argc, argv, multipath);
		}
#endif
#ifdef DBMULTI_dbclient
		if (strcmp(progname, "dbclient") == 0
				|| strcmp(progname, "ssh") == 0) {
			return cli_main(argc, argv);
		}
#endif
#ifdef DBMULTI_dropbearkey
		if (strcmp(progname, "dropbearkey") == 0
				|| strcmp(progname, "ssh-keygen") == 0) {
			return dropbearkey_main(argc, argv);
		}
#endif
#ifdef DBMULTI_dropbearconvert
		if (strcmp(progname, "dropbearconvert") == 0) {
			return dropbearconvert_main(argc, argv);
		}
#endif
#ifdef DBMULTI_scp
		if (strcmp(progname, "scp") == 0) {
			return scp_main(argc, argv);
		}
#endif
	*match = DROPBEAR_FAILURE;
	return 1;
}

int main(int argc, char ** argv) {
	int i;
#ifdef DROPBEAR_WIN32_NATIVE
	{
		int native_result = run_native_internal(argc, argv);
		if (native_result >= 0) return native_result;
	}
#endif
	for (i = 0; i < 2; i++) {
		const char* multipath = NULL;
		if (i == 1) {
			multipath = argv[0];
		}
		/* Try symlink first, then try as an argument eg "dropbearmulti dbclient host ..." */
		if (argc > i) {
			int match, res;
			/* figure which form we're being called as */
			const char* progname = basename(argv[i]);
			res = runprog(multipath, progname, argc-i, &argv[i], &match);
			if (match == DROPBEAR_SUCCESS) {
				return res;
			}
		}
	}

#if defined(DROPBEAR_WIN32_NATIVE) && defined(DBMULTI_dropbear)
	/* Native deliverables run the server regardless of the architecture suffix. */
	return dropbear_main(argc, argv, NULL);
#endif

	fprintf(stderr, "Dropbear SSH multi-purpose v%s\n"
			"Make a symlink pointing at this binary with one of the\n"
			"following names or run 'dropbearmulti <command>'.\n"
#ifdef DBMULTI_dropbear
			"'dropbear' - the Dropbear server\n"
#endif
#ifdef DBMULTI_dbclient
			"'dbclient' or 'ssh' - the Dropbear client\n"
#endif
#ifdef DBMULTI_dropbearkey
			"'dropbearkey' or 'ssh-keygen' - the key generator\n"
#endif
#ifdef DBMULTI_dropbearconvert
			"'dropbearconvert' - the key converter\n"
#endif
#ifdef DBMULTI_scp
			"'scp' - secure copy\n"
#endif
			,
			DROPBEAR_VERSION);
	exit(1);

}
