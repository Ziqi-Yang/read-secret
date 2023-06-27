# Read Secret

[docs](https://docs.rs/read-secret)

A rust library that provides an easy way to read and decrypt secrets from your environment variables and files. 

Code is hosted on [sourcehut](https://git.sr.ht/~meow_king/read-secret), and it is recommended to open issues/send patches on this platform. However, GitHub is also acceptable.

## Usage

Run command `cargo add read-secret` or put the following code into your `cargo.toml`

``` toml
[dependencies]
read-secret = <version>
```

## Example 

This example code is in file `examples/e1.es`, and you can run it by executing `cargo run --example e1`
``` rust
use read_secret::{DecryptMethod, SecretType};
use std::process::Command;

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

## Bugs, features, feedback, and contributions

### Questions and general feedback

Send a (plain text) email to [the mailing list for discussion](https://lists.sr.ht/~meow_king/discussion).  
[Mailing list etiquette](https://man.sr.ht/lists.sr.ht/etiquette.md)

### Bugs and feature 

Submit a ticket to the [tracker](https://todo.sr.ht/~meow_king/read-secret).

### Pull requests, patches

Send patches to [my mailing list for development](https://lists.sr.ht/~meow_king/dev), or use GitHub if you want.   
How to send a patch? Here are some useful resources you can utilize:
- [Using git-send-email for sending and reviewing patches on sr.ht](https://man.sr.ht/git.sr.ht/send-email.md)



