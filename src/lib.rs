//! This rust library provides an easy way to read secrets from your environment and file.
//! It also allows you to use external command like GPG to read keys.

use std::{
    env::{self, VarError},
    error::Error,
    fs::File,
    io::{self, Read, Write},
    path::Path,
		process::{Command, Stdio, Child},
};

/// Type of Secret:
pub enum SecretType {
    /// environment variable name
    Env(String),
    /// file path NOTE: relative to ... or absolute
    File(String),
    /// secret string
    String(String),
}

/// Method to decrypt a encoded secret
pub enum DecryptMethod<'a> {
    /// do nothing
    None,
    GPG,
    /// Custom command used to decrypt a secret
    Custom(&'a mut Command),
}

/// Provide an common entry to read secret
pub fn read_secret(stype: SecretType, dm: &mut DecryptMethod) -> Result<String, Box<dyn Error>> {
    match stype {
        SecretType::Env(name) => {
						let origin = read_env(&name)
								.map_err(|e| Box::new(e) as Box<dyn Error>)?;
						decrypt(origin, dm)
								.map_err(|e| Box::new(e) as Box<dyn Error>)
				},
				SecretType::File(path) => {
						let origin = read_file(&path)
								.map_err(|e| Box::new(e) as Box<dyn Error>)?;
						decrypt(origin, dm)
								.map_err(|e| Box::new(e) as Box<dyn Error>)
				},
        SecretType::String(secret) => Ok(secret),
    }
}

/// Get a value of the given environment variable. If the given environment variable doesn't exist,
/// env::VarError will be returned.
pub fn read_env(env_name: &str) -> Result<String, VarError> {
    env::var(env_name)
}

/// NOTE: path relative to ... or absolute path
pub fn read_file(path: &str) -> io::Result<String> {
    let path = Path::new(path);
    let mut buf = String::new();
    File::open(path)?.read_to_string(&mut buf)?;
    Ok(buf)
}

/// Decrypt a encoded password using provided method
fn decrypt(estr: String, dm: &mut DecryptMethod) -> io::Result<String> {
		match dm {
				DecryptMethod::None => Ok(estr),
				DecryptMethod::GPG => {
						let gpg = Command::new("gpg")
								.args(["--no-tty", "-q", "-d", "-a"])
								.stdin(Stdio::piped())
								.stdout(Stdio::piped())
								.spawn()
								.expect("Failed to spawn `gpg`: please ensure you have it installed.");
						let res = get_command_output(gpg, estr)?;
						// remove the tailing new line character
						let res = res.chars().take(res.len() - 1).collect();
						Ok(res)
				},
				DecryptMethod::Custom(command) => {
						let command = command
								.stdin(Stdio::piped())
								.stdout(Stdio::piped())
								.spawn().expect("Failed to spawn command");
						get_command_output(command, estr)
				},
		}
}

fn get_command_output(mut command: Child, input: String) -> io::Result<String> {
		let mut stdin = (&mut command).stdin.take().expect("Failed to take stdin");
		stdin.write_all(input.as_bytes())?;
		drop(stdin);
		let output = command.wait_with_output()?;
		let res = String::from_utf8(output.stdout)
				.expect("Cannot convert utf8 bytes into String.");
		Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    const LIB_VERSION: &str = "0.1.0";

    #[test]
    fn test_read_secret() -> Result<(), Box<dyn Error>> {
				let mut dm = DecryptMethod::None;
        let st = SecretType::Env("CARGO_PKG_VERSION".to_string());
        let sr = read_secret(st, &mut dm)?;
        assert_eq!(LIB_VERSION, sr);
        Ok(())
    }

    #[test]
    fn test_read_env() -> Result<(), VarError> {
        // pass case
        let s = read_env("CARGO_PKG_VERSION")?;
        assert_eq!(LIB_VERSION, s);
        // failed case
        let failed = read_env("UNEXISTED_VALUE");
        assert!(failed.is_err());
        Ok(())
    }

    #[test]
    fn test_read_file() -> io::Result<()> {
        let sl = "El Psy Kongaroo";
        let sr = read_file("tests/pass_0")?;
        assert_eq!(sl, sr);
        Ok(())
    }

		#[test]
		fn test_decrypt() -> io::Result<()> {
				let sl = "El Psy Kongaroo";
				// DecryptMethod::None
				let mut dm = DecryptMethod::None;
				let sr = sl;
				let sr = decrypt(sr.to_string(), &mut dm)?;
				assert_eq!(sr, sl);
				
				// DecryptMethod::GPG
				let mut dm = DecryptMethod::GPG;
				let sr = "-----BEGIN PGP MESSAGE-----

hQGMAw4MNp4TmOFvAQwAuXN8xO+ca+Bz8bEFqnEB8cuxKYd0rCLa7UqN446DLnbj
0g5IqyfhCgzNgbMN9LN3pYALwPrNEw6bSK6QoOn3ZtCOQKRSjH1WprRGUx3Fc+dO
gDy8B79twcQyPFsy+3PbfDgQjxciNGuCXKBEp/cr+QFjAgX+wPTmoYv3xZGLHX5G
tAsE9bB00AeyUdedDbn+V1YUW8mTZko4JtvXst3pRhaBHlina+MdaoFaQLzAhN0A
jaVMrrm/L+WWAvrbdJvs8ew7QprENch2J0rXT5BY9tL8QRTnTLqrczQXtCLXMdk6
nELkVDEvj/FloVKgGK10wj62eRgIp2eZOxY5GRkB6U8VEuDVzy9ryNWm8qiachsB
GhibFWgjXOGxq/kEcmwZbzOC01KuqiGpI0MiGz3492detV2K2YGXsgbRZUwxb44B
X0MFE43HySxRGdYZ7Q5E0HClTQedNw1YCo82DpELheGA9GOe1taQjX+gd98h5Fp0
fmvb8an9JMgXwJDb0EHO0ksB6CaAfueLAR4sL8OpmUbeVg/kJv9fgvkHXvMMnFp+
BafOEV3SWmeMynyfYk2g12wtph+Jm9EDq3PLokHAlfp0EYRqTSF0VDaHYdw=
=LM7a
-----END PGP MESSAGE-----";
				let sr = decrypt(sr.to_string(), &mut dm)?;
				assert_eq!(sl, sr);
				
				// DecryptMethod::Custom
				let mut binding = Command::new("wc");
				let custom_command = binding.args(["-c"]);
				let mut dm = DecryptMethod::Custom(custom_command);
				let sr = sl;
				let sr = decrypt(sr.to_string(), &mut dm)?;
				assert_eq!("15\n", sr);
				Ok(())
		}
}

