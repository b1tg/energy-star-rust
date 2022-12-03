use faithe::process as ps;
use faithe::types::access_rights::PROCESS_SET_INFORMATION;
use faithe::types::HWND;
use windows::Win32::UI::Accessibility::SetWinEventHook;
use windows::Win32::UI::Accessibility::HWINEVENTHOOK;
use windows::Win32::UI::Accessibility::WINEVENTPROC;
use windows::Win32::UI::WindowsAndMessaging::DispatchMessageW;
use windows::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId;
use windows::Win32::UI::WindowsAndMessaging::PeekMessageW;
use windows::Win32::UI::WindowsAndMessaging::TranslateMessage;
use windows::Win32::UI::WindowsAndMessaging::EVENT_SYSTEM_FOREGROUND;
use windows::Win32::UI::WindowsAndMessaging::MSG;
use windows::Win32::UI::WindowsAndMessaging::PM_REMOVE;
use windows::Win32::UI::WindowsAndMessaging::WINEVENT_OUTOFCONTEXT;
use windows::Win32::UI::WindowsAndMessaging::WINEVENT_SKIPOWNPROCESS;
// use windows_sys::Win32::System::Threading::PROCESS_SET_INFORMATION;
use std::collections::HashSet;
use std::mem::size_of;
use std::ptr::null_mut;
use std::time::Duration;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::OpenProcess;
use windows::Win32::System::Threading::{
    ProcessPowerThrottling, SetPriorityClass, SetProcessInformation, IDLE_PRIORITY_CLASS,
    NORMAL_PRIORITY_CLASS, PROCESS_POWER_THROTTLING_CURRENT_VERSION,
    PROCESS_POWER_THROTTLING_EXECUTION_SPEED, PROCESS_POWER_THROTTLING_STATE,
};
use windows_sys::Win32::System::Threading::PROCESS_QUERY_INFORMATION;
unsafe fn toggle_efficiency_mode(hprocess: HANDLE, enable: bool) {
    let mut state = PROCESS_POWER_THROTTLING_STATE {
        Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        ControlMask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
        StateMask: 0,
    };
    if enable {
        state.StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
    }
    let res = SetProcessInformation(
        hprocess,
        ProcessPowerThrottling,
        &state as *const _ as _,
        size_of::<PROCESS_POWER_THROTTLING_STATE>() as _,
    );
    if res == false {
        dbg!(GetLastError());
    }
    let res = SetPriorityClass(
        hprocess,
        if enable {
            IDLE_PRIORITY_CLASS
        } else {
            NORMAL_PRIORITY_CLASS
        },
    );
    if res == false {
        dbg!(GetLastError());
    }
}

unsafe extern "system" fn hookProcDelegate(
    hook: HWINEVENTHOOK,
    event_type: u32,
    hwnd: HWND,
    id_object: i32,
    id_child: i32,
    dw_event_thread: u32,
    event_time: u32,
) {
    let mut proc_id = 0;
    let window_thread_id = GetWindowThreadProcessId(hwnd, &mut proc_id as *mut _ as _);
    if proc_id == 0 || window_thread_id == 0 {
        return;
    }

    // let ph = OpenProcess(PROCESS_QUERY_INFORMATION, false, proc_id).unwrap();
    let file_name = ps::ProcessIterator::new()
        .unwrap()
        .find(|p| p.process_id == proc_id)
        .unwrap()
        .file_name;
    dbg!(file_name);
    // ps::ProcessEntry::open(&self, inherit_handle, desired_access)

    // GetProcessNameFromHandle()
}

// from https://github.com/LGUG2Z/komorebi/blob/master/komorebi/src/winevent_listener.rs
#[derive(Debug, Copy, Clone)]
pub struct MessageLoop;

impl MessageLoop {
    pub fn start(sleep: u64, cb: impl Fn(Option<MSG>) -> bool) {
        Self::start_with_sleep(sleep, cb);
    }

    fn start_with_sleep(sleep: u64, cb: impl Fn(Option<MSG>) -> bool) {
        let mut msg: MSG = MSG::default();
        loop {
            let mut value: Option<MSG> = None;
            unsafe {
                if !bool::from(!PeekMessageW(&mut msg, HWND(0), 0, 0, PM_REMOVE)) {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);

                    value = Some(msg);
                }
            }

            std::thread::sleep(Duration::from_millis(sleep));

            if !cb(value) {
                break;
            }
        }
    }
}
fn main() {
    unsafe {
        let windowEventHook = SetWinEventHook(
            EVENT_SYSTEM_FOREGROUND, // eventMin
            EVENT_SYSTEM_FOREGROUND, // eventMax
            None,                    // hmodWinEventProc
            Some(hookProcDelegate),  // lpfnWinEventProc
            0,                       // idProcess
            0,                       // idThread
            WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
        );
    }
    MessageLoop::start(10, |_msg| true);
}
fn throttle_all_user_background_processes() {
    let bypass_list = HashSet::from(
        [
            // Not ourselves
            "energy-star-rust.exe",
            // Edge has energy awareness
            "msedge.exe",
            "WebViewHost.exe",
            // UWP Frame has special handling, should not be throttled
            "ApplicationFrameHost.exe",
            // Fire extinguisher should not catch fire
            "taskmgr.exe",
            "procmon.exe",
            "procmon64.exe",
            // Widgets
            "Widgets.exe",
            // System shell
            "dwm.exe",
            "explorer.exe",
            "ShellExperienceHost.exe",
            "StartMenuExperienceHost.exe",
            "SearchHost.exe",
            "sihost.exe",
            "fontdrvhost.exe",
            // IME
            "ChsIME.exe",
            "ctfmon.exe",
            // Visual Studio
            "devenv.exe",
            // System Service - they have their awareness
            "csrss.exe",
            "smss.exe",
            "svchost.exe",
            // WUDF
            "WUDFRd.exe",
        ]
        .map(|name| name.to_lowercase()),
    );
    let current_pid = std::process::id();
    let current_session_id = pid_to_session_id(current_pid);
    for process_entry in ps::ProcessIterator::new().unwrap() {
        let pid = process_entry.process_id;
        let session_id = pid_to_session_id(pid);
        println!("{} => {}", pid, session_id);
        if session_id == current_session_id
            && !bypass_list.contains(process_entry.file_name.to_lowercase().as_str())
        {
            let process = process_entry.open(false, PROCESS_SET_INFORMATION).unwrap();
            unsafe {
                toggle_efficiency_mode(process.handle(), true);
            }
        }
    }
}

fn pid_to_session_id(pid: u32) -> u32 {
    let mut session_id = 0;
    unsafe {
        ProcessIdToSessionId(pid, &mut session_id as *mut _ as _);
    }
    return session_id;
}

#[test]
fn test_process() {
    let process = ps::ProcessIterator::new()
        .unwrap()
        .find(|p| p.file_name.to_lowercase() == "notepad.exe")
        .unwrap()
        .open(false, PROCESS_SET_INFORMATION)
        .unwrap();
    println!("{}", process.id());
    unsafe {
        // let process = OpenProcess(PROCESS_SET_INFORMATION,false , 45804).unwrap();
        toggle_efficiency_mode(process.handle(), true);
    }
}
