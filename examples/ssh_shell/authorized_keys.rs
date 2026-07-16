//! Parsing for an OpenSSH `authorized_keys` file.

use russh::keys::{PublicKey, ssh_key};

/// The set of public keys permitted to authenticate.
#[derive(Debug, Default)]
pub struct AuthorizedKeys(Vec<PublicKey>);

/// A line of an `authorized_keys` file that could not be parsed.
#[derive(thiserror::Error, Debug)]
#[error("{path}:{line}: {source}")]
pub struct ParseError {
    path: String,
    line: usize,
    source: ssh_key::Error,
}

impl AuthorizedKeys {
    /// Parse the contents of an `authorized_keys` file.
    ///
    /// Blank lines and `#` comments are skipped. `path` is used only to label errors.
    ///
    /// Note that per-key options (the optional `command="..."`,`no-pty`,... prefix that
    /// OpenSSH allows before the key type) are not supported: a line carrying options is a
    /// parse error rather than a silently ignored restriction, since accepting the key while
    /// dropping its restrictions would be the unsafe reading of the file.
    pub fn parse(path: &str, contents: &str) -> Result<Self, ParseError> {
        contents
            .lines()
            .enumerate()
            .map(|(idx, line)| (idx + 1, line.trim()))
            .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
            .map(|(line, text)| {
                PublicKey::from_openssh(text).map_err(|source| ParseError {
                    path: path.to_owned(),
                    line,
                    source,
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }

    /// Whether `offered` is one of the authorized keys.
    ///
    /// Compares the key data only: the comment and any trailing whitespace of the
    /// `authorized_keys` line are not part of the key's identity, and the client never sends
    /// them.
    pub fn contains(&self, offered: &PublicKey) -> bool {
        self.0.iter().any(|k| k.key_data() == offered.key_data())
    }

    /// The number of authorized keys.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
mod tests {
    use russh::keys::PublicKey;

    use super::AuthorizedKeys;

    // Two distinct, valid ed25519 public keys, in the exact shape ssh-keygen emits.
    const KEY_A: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDbBXePAbgJ0e6+qv2P0QPUSSVjdL9Mm6uHZrXsL6NPF a@example";
    const KEY_B: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKvW6XLvcgrH3g0WArEiajHO4eZ0abT+d3xOAnkG47iK b@example";

    #[test]
    fn parses_a_file_of_keys_ignoring_comments_and_blank_lines() {
        let scenarios = [
            ("a single key", format!("{KEY_A}\n"), 1),
            ("several keys", format!("{KEY_A}\n{KEY_B}\n"), 2),
            ("an empty file", String::new(), 0),
            (
                "comments and blank lines interleaved",
                format!("# leading comment\n\n{KEY_A}\n\n   # indented comment\n{KEY_B}\n\n"),
                2,
            ),
            (
                "a final line with no trailing newline",
                format!("{KEY_A}\n{KEY_B}"),
                2,
            ),
            (
                "lines padded with whitespace",
                format!("   {KEY_A}   \n\t{KEY_B}\t\n"),
                2,
            ),
        ];

        for (desc, contents, expected) in scenarios {
            let keys = AuthorizedKeys::parse("authorized_keys", &contents)
                .unwrap_or_else(|e| panic!("parsing {desc}: {e}"));

            assert_eq!(keys.len(), expected, "parsing {desc}");
        }
    }

    #[test]
    fn rejects_a_file_containing_an_unparseable_line() {
        let scenarios = [
            ("a truncated key", format!("{KEY_A}\nssh-ed25519 AAAA\n")),
            ("a line of prose", "not a key at all\n".to_owned()),
            (
                // Options are a real authorized_keys feature we do not implement. Accepting
                // the key while ignoring `command=` would run the wrong thing entirely.
                "a key carrying options",
                format!("command=\"/bin/true\",no-pty {KEY_A}\n"),
            ),
        ];

        for (desc, contents) in scenarios {
            let result = AuthorizedKeys::parse("authorized_keys", &contents);

            assert!(result.is_err(), "expected {desc} to be rejected");
        }
    }

    #[test]
    fn error_identifies_the_offending_line() {
        let contents = format!("{KEY_A}\n\n# comment\nssh-ed25519 bogus\n");

        let err = AuthorizedKeys::parse("/etc/ssh_shell/authorized_keys", &contents)
            .expect_err("expected a parse error");

        assert!(
            err.to_string()
                .starts_with("/etc/ssh_shell/authorized_keys:4:"),
            "error should point at line 4, got: {err}"
        );
    }

    #[test]
    fn authorizes_only_the_keys_in_the_file() {
        let keys = AuthorizedKeys::parse("authorized_keys", &format!("{KEY_A}\n")).unwrap();

        assert!(keys.contains(&PublicKey::from_openssh(KEY_A).unwrap()));
        assert!(!keys.contains(&PublicKey::from_openssh(KEY_B).unwrap()));
    }

    #[test]
    fn authorizes_a_key_whose_comment_differs_from_the_file() {
        // The client offers a bare key; the comment in the file is local metadata and must
        // not affect the match.
        let keys = AuthorizedKeys::parse("authorized_keys", &format!("{KEY_A}\n")).unwrap();
        let offered = KEY_A.rsplit_once(' ').unwrap().0;

        assert!(keys.contains(&PublicKey::from_openssh(offered).unwrap()));
    }
}
