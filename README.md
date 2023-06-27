# Read Secret

[docs](https://docs.rs/read-secret)

An rust library that provides an easy way to read secrets from your environment and file. 

Code is hosted on [sourcehut](https://git.sr.ht/~meow_king/read-secret), and it is recommended to open issues/send patches on this platform. However, GitHub is also acceptable.

## Usage

Put the following code into your `cargo.toml`

``` toml
[dependencies]
read-secret = "0.1"
```

## Example 

This example code is in file `examples/e1.es`, and you can run it by executing `cargo run --example e1`
``` rust
use std::process::Command;
use read_secret::{
		DecryptMethod, SecretType
};

fn main() {
		// read secret from environment variable.
		let mut dm = DecryptMethod::None;
    let st = SecretType::Env("XDG_SESSION_TYPE".to_string());
    let sr = read_secret::read_secret(st, &mut dm).unwrap();
    assert_eq!("wayland", sr);

		// read secret from file and decrypt it using gnupg.
		let mut dm = DecryptMethod::GPG;
    let st = SecretType::File("examples/pass_gpg.asc".to_string());
    let sr = read_secret::read_secret(st, &mut dm).unwrap();
    assert_eq!("El Psy Kongaroo", sr);

		// store encrypted secret inside string and decrypt it using custom command.
		let mut temp = Command::new("wc"); // avoid E0716 -- temporary value is being dropped
		let custom_command = temp.args(["-c"]);
		let mut dm = DecryptMethod::Custom(custom_command);
    let st = SecretType::String("El Psy Kongaroo".to_string());
    let sr = read_secret::read_secret(st, &mut dm).unwrap();
    assert_eq!("15\n", sr);
}
```

