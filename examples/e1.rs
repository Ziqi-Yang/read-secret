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
