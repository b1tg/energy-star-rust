use faithe::process as ps;
use faithe::types::access_rights::PROCESS_SET_INFORMATION;
use std::mem::size_of;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{
    ProcessPowerThrottling, SetPriorityClass, SetProcessInformation, IDLE_PRIORITY_CLASS,
    NORMAL_PRIORITY_CLASS, PROCESS_POWER_THROTTLING_CURRENT_VERSION,
    PROCESS_POWER_THROTTLING_EXECUTION_SPEED, PROCESS_POWER_THROTTLING_STATE,
};

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

fn main() {
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
