use std::env;
use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};

pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;
pub const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
pub const HIGH_PRIORITY_CLASS: u32 = 0x0000_0080;
pub const ABOVE_NORMAL_PRIORITY_CLASS: u32 = 0x0000_8000;
pub const NORMAL_PRIORITY_CLASS: u32 = 0x0000_0020;
pub const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x0000_4000;
pub const IDLE_PRIORITY_CLASS: u32 = 0x0000_0040;
pub const REALTIME_PRIORITY_CLASS: u32 = 0x0000_0100;

const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const PROCESS_TERMINATE: u32 = 0x0001;
const STILL_ACTIVE: u32 = 259;
const WAIT_OBJECT_0: u32 = 0x0000_0000;
const ERROR_ALREADY_EXISTS: i32 = 183;

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    lp_reserved: *mut u16,
    lp_desktop: *mut u16,
    lp_title: *mut u16,
    dw_x: u32,
    dw_y: u32,
    dw_x_size: u32,
    dw_y_size: u32,
    dw_x_count_chars: u32,
    dw_y_count_chars: u32,
    dw_fill_attribute: u32,
    dw_flags: u32,
    w_show_window: u16,
    cb_reserved2: u16,
    lp_reserved2: *mut u8,
    h_std_input: *mut c_void,
    h_std_output: *mut c_void,
    h_std_error: *mut c_void,
}

#[repr(C)]
struct ProcessInformation {
    h_process: *mut c_void,
    h_thread: *mut c_void,
    dw_process_id: u32,
    dw_thread_id: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn SetPriorityClass(h_process: *mut c_void, dw_priority_class: u32) -> i32;
    fn GetPriorityClass(h_process: *mut c_void) -> u32;
    fn WaitForSingleObject(h_handle: *mut c_void, dw_milliseconds: u32) -> u32;
    fn CreateMutexW(lp_mutex_attributes: *mut c_void, b_initial_owner: i32, lp_name: *const u16) -> *mut c_void;
    fn CloseHandle(h_object: *mut c_void) -> i32;
    fn SetConsoleCtrlHandler(
        handler_routine: Option<unsafe extern "system" fn(u32) -> i32>,
        add: i32,
    ) -> i32;
    fn OpenProcess(dw_desired_access: u32, b_inherit_handle: i32, dw_process_id: u32) -> *mut c_void;
    fn TerminateProcess(h_process: *mut c_void, u_exit_code: u32) -> i32;
    fn GetExitCodeProcess(h_process: *mut c_void, lp_exit_code: *mut u32) -> i32;
    fn CreateProcessW(
        lp_application_name: *const u16,
        lp_command_line: *mut u16,
        lp_process_attributes: *mut c_void,
        lp_thread_attributes: *mut c_void,
        b_inherit_handles: i32,
        dw_creation_flags: u32,
        lp_environment: *mut c_void,
        lp_current_directory: *const u16,
        lp_startup_info: *const StartupInfoW,
        lp_process_information: *mut ProcessInformation,
    ) -> i32;
}

static CTRL_TRIGGERED: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn ctrl_handler(_ctrl_type: u32) -> i32 {
    CTRL_TRIGGERED.store(true, Ordering::SeqCst);
    1
}

pub fn install_ctrl_handler() {
    unsafe {
        let _ = SetConsoleCtrlHandler(Some(ctrl_handler), 1);
    }
}

pub fn ctrl_triggered() -> bool {
    CTRL_TRIGGERED.load(Ordering::SeqCst)
}

pub fn set_current_high_priority() -> bool {
    unsafe { SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS) != 0 }
}

pub fn priority_class_name(cls: u32) -> &'static str {
    match cls {
        REALTIME_PRIORITY_CLASS => "REALTIME",
        HIGH_PRIORITY_CLASS => "HIGH",
        ABOVE_NORMAL_PRIORITY_CLASS => "ABOVE_NORMAL",
        NORMAL_PRIORITY_CLASS => "NORMAL",
        BELOW_NORMAL_PRIORITY_CLASS => "BELOW_NORMAL",
        IDLE_PRIORITY_CLASS => "IDLE",
        _ => "UNKNOWN",
    }
}

pub fn process_priority_name(pid: u32) -> Option<&'static str> {
    if pid == 0 {
        return None;
    }
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let cls = GetPriorityClass(h);
        CloseHandle(h);
        if cls == 0 {
            None
        } else {
            Some(priority_class_name(cls))
        }
    }
}

/// Instant event-driven wait on a Child process handle (0ms exit wakeup, zero busy polling).
/// Returns true if the process has exited, false on timeout slice.
pub fn wait_child_ms(child: &Child, timeout_ms: u32) -> bool {
    unsafe { WaitForSingleObject(child.as_raw_handle() as *mut c_void, timeout_ms) == WAIT_OBJECT_0 }
}

pub struct NamedMutex {
    handle: *mut c_void,
}

impl NamedMutex {
    pub fn try_acquire(name: &str) -> Result<Option<Self>, String> {
        let wide: Vec<u16> = OsStr::new(name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            let h = CreateMutexW(std::ptr::null_mut(), 1, wide.as_ptr());
            if h.is_null() {
                return Err(format!(
                    "CreateMutexW failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if std::io::Error::last_os_error().raw_os_error() == Some(ERROR_ALREADY_EXISTS) {
                CloseHandle(h);
                return Ok(None);
            }
            Ok(Some(Self { handle: h }))
        }
    }
}

impl Drop for NamedMutex {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_null() {
                CloseHandle(self.handle);
                self.handle = std::ptr::null_mut();
            }
        }
    }
}

pub fn process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return false;
        }
        let mut code: u32 = 0;
        let ok = GetExitCodeProcess(h, &mut code);
        CloseHandle(h);
        ok != 0 && code == STILL_ACTIVE
    }
}

pub fn kill_pid(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if h.is_null() {
            return false;
        }
        let ok = TerminateProcess(h, 1);
        CloseHandle(h);
        ok != 0
    }
}

fn quote_win_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.chars().any(|c| c == ' ' || c == '\t' || c == '"') {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut bs = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            bs += 1;
        } else if ch == '"' {
            for _ in 0..(bs * 2 + 1) {
                out.push('\\');
            }
            out.push('"');
            bs = 0;
        } else {
            for _ in 0..bs {
                out.push('\\');
            }
            bs = 0;
            out.push(ch);
        }
    }
    for _ in 0..(bs * 2) {
        out.push('\\');
    }
    out.push('"');
    out
}

pub fn spawn_detached_no_inherit(exe: &str, args: &[&str], high_priority: bool) -> Result<u32, String> {
    let mut cmdline = quote_win_arg(exe);
    for a in args {
        cmdline.push(' ');
        cmdline.push_str(&quote_win_arg(a));
    }
    let exe_w: Vec<u16> = OsStr::new(exe)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut cmd_w: Vec<u16> = OsStr::new(&cmdline)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut flags = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP;
    if high_priority {
        flags |= HIGH_PRIORITY_CLASS;
    }
    unsafe {
        let mut si: StartupInfoW = std::mem::zeroed();
        si.cb = std::mem::size_of::<StartupInfoW>() as u32;
        let mut pi: ProcessInformation = std::mem::zeroed();
        let ok = CreateProcessW(
            exe_w.as_ptr(),
            cmd_w.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0, // bInheritHandles = FALSE: never leak caller stdio pipes
            flags,
            std::ptr::null_mut(),
            std::ptr::null(),
            &si,
            &mut pi,
        );
        if ok == 0 {
            return Err(format!(
                "CreateProcessW failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let pid = pi.dw_process_id;
        CloseHandle(pi.h_thread);
        CloseHandle(pi.h_process);
        Ok(pid)
    }
}

pub fn system_data_dir() -> PathBuf {
    if let Ok(pd) = env::var("ProgramData") {
        if !pd.is_empty() {
            return PathBuf::from(pd).join("wsl-bridge");
        }
    }
    PathBuf::from(r"C:\ProgramData\wsl-bridge")
}

pub fn user_data_dir() -> PathBuf {
    if let Ok(local) = env::var("LOCALAPPDATA") {
        if !local.is_empty() {
            return PathBuf::from(local).join("wsl-bridge");
        }
    }
    if let Ok(profile) = env::var("USERPROFILE") {
        if !profile.is_empty() {
            return PathBuf::from(profile)
                .join("AppData")
                .join("Local")
                .join("wsl-bridge");
        }
    }
    env::temp_dir().join("wsl-bridge")
}

pub fn local_data_dir() -> PathBuf {
    let sys_dir = system_data_dir();
    if sys_dir.is_dir() {
        return sys_dir;
    }
    user_data_dir()
}

const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6;
const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5;

#[link(name = "kernel32")]
extern "system" {
    fn GetStdHandle(n_std_handle: u32) -> *mut c_void;
    fn GetConsoleMode(h_console_handle: *mut c_void, lp_mode: *mut u32) -> i32;
}

#[link(name = "advapi32")]
extern "system" {
    fn SystemFunction036(random_buffer: *mut u8, random_buffer_length: u32) -> u8;
}

/// Returns true when either stdin or stdout is attached to an interactive Windows console TTY.
pub fn is_console_tty() -> bool {
    unsafe {
        let mut mode: u32 = 0;
        let hin = GetStdHandle(STD_INPUT_HANDLE);
        if !hin.is_null() && GetConsoleMode(hin, &mut mode) != 0 {
            return true;
        }
        let hout = GetStdHandle(STD_OUTPUT_HANDLE);
        if !hout.is_null() && GetConsoleMode(hout, &mut mode) != 0 {
            return true;
        }
        false
    }
}

pub fn random_token_hex() -> String {
    let mut bytes = [0u8; 32];
    unsafe {
        let _ = SystemFunction036(bytes.as_mut_ptr(), bytes.len() as u32);
    }
    let mut out = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}
