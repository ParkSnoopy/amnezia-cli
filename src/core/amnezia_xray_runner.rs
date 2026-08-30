use std::{
    ffi::{
        CString,
        c_char,
        c_int,
        c_void,
    },
    fs,
    process::{
        Command,
        ExitCode,
    },
    sync::atomic::{
        AtomicBool,
        Ordering,
    },
    time::Duration,
};

const SIGINT: c_int = 2;
const SIGTERM: c_int = 15;
const MAX_CONFIGURATION_BYTES: usize = 16 * 1024 * 1024;

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    fn amnezia_xray_free(pointer: *mut c_void);
    fn amnezia_xray_configure(configuration: *mut c_char) -> *mut c_char;
    fn amnezia_xray_start() -> *mut c_char;
    fn amnezia_xray_stop() -> *mut c_char;
    fn signal(number: c_int, handler: extern "C" fn(c_int)) -> usize;
}

extern "C" fn request_stop(_signal: c_int) {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
}

fn xray_call(operation: &str, error: *mut c_char) -> Result<(), String> {
    if error.is_null() {
        return Ok(());
    }
    unsafe { amnezia_xray_free(error.cast()) };
    Err(format!("XRay {operation} failed"))
}

fn run(arguments: &[String]) -> Result<(), String> {
    if arguments.len() == 2 && arguments[1] == "--check" {
        return Ok(());
    }
    if arguments.len() != 7 {
        return Err("internal XRay runner expects configuration, tun2socks, interface, endpoint, gateway, and uplink".into());
    }

    let configuration =
        fs::read(&arguments[1]).map_err(|_| "cannot read staged XRay configuration")?;
    if configuration.is_empty() || configuration.len() > MAX_CONFIGURATION_BYTES {
        return Err("staged XRay configuration has an invalid size".into());
    }
    let configuration = CString::new(configuration)
        .map_err(|_| "staged XRay configuration contains a null byte")?;
    xray_call("configure", unsafe {
        amnezia_xray_configure(configuration.as_ptr().cast_mut())
    })?;
    xray_call("start", unsafe { amnezia_xray_start() })?;

    unsafe {
        signal(SIGTERM, request_stop);
        signal(SIGINT, request_stop);
    }

    let device = format!("tun://{}", arguments[3]);
    let mut child = match Command::new(&arguments[2])
        .args(["-device", &device, "-proxy", "socks5://127.0.0.1:10808"])
        .spawn()
    {
        Ok(child) => child,
        Err(_) => {
            let _ = xray_call("stop", unsafe { amnezia_xray_stop() });
            return Err("cannot start tun2socks".into());
        }
    };

    let child_result = loop {
        if STOP_REQUESTED.load(Ordering::SeqCst) {
            let _ = child.kill();
            break child.wait().map(|_| ());
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break Ok(()),
            Ok(Some(_)) => break Err(std::io::Error::other("tun2socks exited unsuccessfully")),
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(error);
            }
        }
    };
    let stop_result = xray_call("stop", unsafe { amnezia_xray_stop() });
    if child_result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    stop_result?;
    child_result.map_err(|error| error.to_string())
}

fn main() -> ExitCode {
    match run(&std::env::args().collect::<Vec<_>>()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
