use std::env;

pub fn strip_win_extended_prefix(p: &str) -> &str {
    if let Some(rest) = p.strip_prefix(r"\\?\UNC\") {
        return rest;
    }
    if let Some(rest) = p.strip_prefix(r"\\?\") {
        return rest;
    }
    p
}

pub fn is_windows_drive_path(s: &str) -> bool {
    let s = strip_win_extended_prefix(s);
    let b = s.as_bytes();
    if b.len() < 2 {
        return false;
    }
    if !b[0].is_ascii_alphabetic() || b[1] != b':' {
        return false;
    }
    b.len() == 2 || b[2] == b'\\' || b[2] == b'/'
}

pub fn win_to_linux(input: &str) -> String {
    let s = strip_win_extended_prefix(input);
    if is_windows_drive_path(s) {
        let drive = (s.as_bytes()[0] as char).to_ascii_lowercase();
        let rest = &s[2..];
        let norm = rest.replace('\\', "/");
        if norm.is_empty() || norm == "/" {
            return format!("/mnt/{}", drive);
        }
        let trimmed = norm.trim_start_matches('/');
        return format!("/mnt/{}/{}", drive, trimmed);
    }
    if s.starts_with('/') {
        let b = s.as_bytes();
        if b.len() >= 2 && b[1].is_ascii_alphabetic() && (b.len() == 2 || b[2] == b'/') {
            let drive = (b[1] as char).to_ascii_lowercase();
            let rest = &s[2..];
            if rest.is_empty() {
                return format!("/mnt/{}", drive);
            }
            return format!("/mnt/{}{}", drive, rest);
        }
    }
    s.to_string()
}

pub fn linux_to_win(input: &str, mixed: bool) -> String {
    let sep = if mixed { '/' } else { '\\' };
    if let Some(rest) = input.strip_prefix("/mnt/") {
        let b = rest.as_bytes();
        if !b.is_empty() && b[0].is_ascii_alphabetic() && (b.len() == 1 || b[1] == b'/') {
            let drive = (b[0] as char).to_ascii_uppercase();
            let tail = if b.len() > 1 { &rest[2..] } else { "" };
            if tail.is_empty() {
                return format!("{}:{}", drive, sep);
            }
            let converted = if mixed {
                tail.to_string()
            } else {
                tail.replace('/', "\\")
            };
            return format!("{}:{}{}", drive, sep, converted);
        }
    }
    if input.starts_with('/') {
        let b = input.as_bytes();
        if b.len() >= 2 && b[1].is_ascii_alphabetic() && (b.len() == 2 || b[2] == b'/') {
            let drive = (b[1] as char).to_ascii_uppercase();
            let tail = if b.len() > 2 { &input[3..] } else { "" };
            if tail.is_empty() {
                return format!("{}:{}", drive, sep);
            }
            let converted = if mixed {
                tail.to_string()
            } else {
                tail.replace('/', "\\")
            };
            return format!("{}:{}{}", drive, sep, converted);
        }
    }
    if is_windows_drive_path(input) {
        let s = strip_win_extended_prefix(input);
        return if mixed {
            s.replace('\\', "/")
        } else {
            s.replace('/', "\\")
        };
    }
    input.to_string()
}

pub fn current_win_dir_clean() -> Option<String> {
    let cwd = env::current_dir().ok()?;
    let s = cwd.to_string_lossy().to_string();
    Some(strip_win_extended_prefix(&s).to_string())
}

pub fn resolve_cwd_for_wsl(cwd: Option<&str>) -> Option<String> {
    if let Some(c) = cwd {
        if c.is_empty() {
            return current_win_dir_clean();
        }
        return Some(strip_win_extended_prefix(c).to_string());
    }
    current_win_dir_clean()
}
