use std::net::IpAddr;

use thiserror::Error;

use crate::domain::model::{
    MAX_CHAT_BODY_BYTES, MAX_DISPLAY_NAME_CHARS, MAX_FILE_TRANSFER_BYTES, MIN_PASSWORD_CHARS,
};

const MAX_SANITIZED_FILENAME_CHARS: usize = 200;
pub const MAX_IDENTIFIER_BYTES: usize = 64;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    #[error("表示名を入力してください")]
    EmptyDisplayName,
    #[error("表示名は{max_chars}文字以内で入力してください（現在{actual_chars}文字）")]
    DisplayNameTooLong {
        max_chars: usize,
        actual_chars: usize,
    },
    #[error("パスワードは{min_chars}文字以上を入力してください（現在{actual_chars}文字）")]
    PasswordTooShort {
        min_chars: usize,
        actual_chars: usize,
    },
    #[error("メッセージ本文を入力してください")]
    EmptyChatBody,
    #[error("メッセージ本文は{max_bytes}バイト以内で入力してください（現在{actual_bytes}バイト）")]
    ChatBodyTooLong {
        max_bytes: usize,
        actual_bytes: usize,
    },
    #[error("識別子の形式または長さが不正です")]
    InvalidIdentifier,
    #[error("ポート番号は1から65535の範囲で指定してください")]
    InvalidPort,
    #[error("有効なIPアドレス（IPv4またはIPv6）を指定してください")]
    InvalidPeerAddress,
    #[error("有効なファイル名を指定してください")]
    InvalidFilename,
    #[error("ファイルサイズは1バイト以上50 MiB以下である必要があります")]
    InvalidFileSize,
    #[error("SHA-256チェックサムの形式が不正です")]
    InvalidSha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordStrength {
    Weak,
    Fair,
    Strong,
}

impl PasswordStrength {
    pub fn label_ja(self) -> &'static str {
        match self {
            Self::Weak => "弱い（8文字以上・英数記号混在を推奨）",
            Self::Fair => "標準（12文字以上・英数記号混在を推奨）",
            Self::Strong => "強い",
        }
    }
}

pub fn validate_and_normalize_display_name(raw: &str) -> Result<String, ValidationError> {
    let cleaned: String = raw.chars().filter(|c| !c.is_control()).collect();
    let trimmed = cleaned.trim().to_string();
    let char_count = trimmed.chars().count();
    if char_count == 0 {
        return Err(ValidationError::EmptyDisplayName);
    }
    if char_count > MAX_DISPLAY_NAME_CHARS {
        return Err(ValidationError::DisplayNameTooLong {
            max_chars: MAX_DISPLAY_NAME_CHARS,
            actual_chars: char_count,
        });
    }
    Ok(trimmed)
}

pub fn validate_password(password: &str) -> Result<(), ValidationError> {
    let actual_chars = password.chars().count();
    if actual_chars < MIN_PASSWORD_CHARS {
        return Err(ValidationError::PasswordTooShort {
            min_chars: MIN_PASSWORD_CHARS,
            actual_chars,
        });
    }
    Ok(())
}

pub fn evaluate_password_strength(password: &str) -> PasswordStrength {
    let len = password.chars().count();
    if len < MIN_PASSWORD_CHARS {
        return PasswordStrength::Weak;
    }

    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;

    for ch in password.chars() {
        if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else {
            has_symbol = true;
        }
    }

    let classes = [has_lower, has_upper, has_digit, has_symbol]
        .into_iter()
        .filter(|&flag| flag)
        .count();

    if len >= 12 && classes >= 3 {
        PasswordStrength::Strong
    } else if len >= 12 || classes >= 2 {
        PasswordStrength::Fair
    } else {
        PasswordStrength::Weak
    }
}

pub fn validate_chat_body(raw: &str) -> Result<String, ValidationError> {
    let unified = raw.replace("\r\n", "\n").replace('\r', "\n");
    let normalized: String = unified
        .chars()
        .filter(|&c| c == '\n' || c == '\t' || !c.is_control())
        .collect();

    if normalized.trim().is_empty() {
        return Err(ValidationError::EmptyChatBody);
    }
    if normalized.len() > MAX_CHAT_BODY_BYTES {
        return Err(ValidationError::ChatBodyTooLong {
            max_bytes: MAX_CHAT_BODY_BYTES,
            actual_bytes: normalized.len(),
        });
    }
    Ok(normalized)
}

pub fn validate_identifier(raw: &str) -> Result<(), ValidationError> {
    if raw.is_empty()
        || raw.len() > MAX_IDENTIFIER_BYTES
        || !raw.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(ValidationError::InvalidIdentifier);
    }
    Ok(())
}

pub fn validate_received_chat_body(body: &str) -> Result<String, ValidationError> {
    validate_chat_body(body)
}

pub fn validate_port(port: u16) -> Result<u16, ValidationError> {
    if port == 0 {
        return Err(ValidationError::InvalidPort);
    }
    Ok(port)
}

pub fn validate_manual_peer_endpoint(
    host: &str,
    port: u16,
) -> Result<(IpAddr, u16), ValidationError> {
    validate_port(port)?;
    let trimmed = host.trim();
    let ip: IpAddr = trimmed
        .parse()
        .map_err(|_| ValidationError::InvalidPeerAddress)?;
    if ip.is_unspecified() || ip.is_multicast() {
        return Err(ValidationError::InvalidPeerAddress);
    }
    Ok((ip, port))
}

fn is_windows_reserved_device_name(stem: &str) -> bool {
    let upper = stem.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

pub fn sanitize_filename(raw: &str) -> Result<String, ValidationError> {
    let leaf = raw.rsplit(['/', '\\']).next().unwrap_or("");
    let trimmed = leaf.trim();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return Err(ValidationError::InvalidFilename);
    }

    let mut sanitized = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        if ch.is_control() {
            continue;
        }
        if matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
            sanitized.push('_');
        } else {
            sanitized.push(ch);
        }
    }

    let cleaned = sanitized.trim().trim_end_matches(['.', ' ']).trim();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        return Err(ValidationError::InvalidFilename);
    }

    let stem = cleaned.split('.').next().unwrap_or("");
    let mut final_name = if is_windows_reserved_device_name(stem) {
        format!("_{cleaned}")
    } else {
        cleaned.to_string()
    };

    if final_name.chars().count() > MAX_SANITIZED_FILENAME_CHARS {
        final_name = final_name
            .chars()
            .take(MAX_SANITIZED_FILENAME_CHARS)
            .collect();
        let retrimmed = final_name.trim_end_matches(['.', ' ']).trim().to_string();
        if retrimmed.is_empty() || retrimmed == "." || retrimmed == ".." {
            return Err(ValidationError::InvalidFilename);
        }
        final_name = retrimmed;
    }

    Ok(final_name)
}

pub fn validate_file_size(size: u64) -> Result<(), ValidationError> {
    if size == 0 || size > MAX_FILE_TRANSFER_BYTES {
        return Err(ValidationError::InvalidFileSize);
    }
    Ok(())
}

pub fn validate_sha256_hex(raw: &str) -> Result<String, ValidationError> {
    if raw.len() != 64 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ValidationError::InvalidSha256);
    }
    Ok(raw.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_name_validation_trims_strips_controls_and_checks_char_len() {
        assert_eq!(
            validate_and_normalize_display_name("  田中\t太郎\n  ").unwrap(),
            "田中太郎"
        );
        assert_eq!(
            validate_and_normalize_display_name("   \r\n\t "),
            Err(ValidationError::EmptyDisplayName)
        );
        let max_32 = "あ".repeat(32);
        assert_eq!(
            validate_and_normalize_display_name(&max_32).unwrap(),
            max_32
        );
        let over_33 = "あ".repeat(33);
        assert_eq!(
            validate_and_normalize_display_name(&over_33),
            Err(ValidationError::DisplayNameTooLong {
                max_chars: 32,
                actual_chars: 33,
            })
        );
    }

    #[test]
    fn password_validation_and_strength_check() {
        assert_eq!(
            validate_password("1234567"),
            Err(ValidationError::PasswordTooShort {
                min_chars: 8,
                actual_chars: 7,
            })
        );
        assert!(validate_password("12345678").is_ok());
        assert!(validate_password("  pass  ").is_ok());

        assert_eq!(
            evaluate_password_strength("1234567"),
            PasswordStrength::Weak
        );
        assert_eq!(
            evaluate_password_strength("12345678"),
            PasswordStrength::Weak
        );
        assert_eq!(
            evaluate_password_strength("abcd1234"),
            PasswordStrength::Fair
        );
        assert_eq!(
            evaluate_password_strength("Abcd1234!@#xyz"),
            PasswordStrength::Strong
        );
    }

    #[test]
    fn chat_body_validation_respects_4kib_utf8_boundary() {
        let normalized = validate_chat_body("行1\r\n行2\r\t項目\x07").unwrap();
        assert_eq!(normalized, "行1\n行2\n\t項目");

        assert_eq!(
            validate_chat_body("  \r\n\t  "),
            Err(ValidationError::EmptyChatBody)
        );

        let exact_4096 = "a".repeat(4096);
        assert_eq!(validate_chat_body(&exact_4096).unwrap().len(), 4096);

        let over_4097 = "a".repeat(4097);
        assert_eq!(
            validate_chat_body(&over_4097),
            Err(ValidationError::ChatBodyTooLong {
                max_bytes: 4096,
                actual_bytes: 4097,
            })
        );

        // 日本語3バイト文字 × 1365 = 4095バイト (OK)、1366文字 = 4098バイト (NG)
        let ja_ok = "あ".repeat(1365);
        assert_eq!(validate_chat_body(&ja_ok).unwrap().len(), 4095);
        let ja_ng = "あ".repeat(1366);
        assert_eq!(
            validate_chat_body(&ja_ng),
            Err(ValidationError::ChatBodyTooLong {
                max_bytes: 4096,
                actual_bytes: 4098,
            })
        );
    }

    #[test]
    fn manual_peer_endpoint_validation_accepts_ip_only() {
        let (v4, p4) = validate_manual_peer_endpoint(" 192.168.1.50 ", 45101).unwrap();
        assert_eq!(v4.to_string(), "192.168.1.50");
        assert_eq!(p4, 45101);

        let (v6, p6) = validate_manual_peer_endpoint("fe80::1", 45102).unwrap();
        assert_eq!(v6.to_string(), "fe80::1");
        assert_eq!(p6, 45102);

        assert_eq!(
            validate_manual_peer_endpoint("192.168.1.50", 0),
            Err(ValidationError::InvalidPort)
        );
        assert_eq!(
            validate_manual_peer_endpoint("0.0.0.0", 45101),
            Err(ValidationError::InvalidPeerAddress)
        );
        assert_eq!(
            validate_manual_peer_endpoint("224.0.0.1", 45101),
            Err(ValidationError::InvalidPeerAddress)
        );
        assert_eq!(
            validate_manual_peer_endpoint("pc-host.local", 45101),
            Err(ValidationError::InvalidPeerAddress)
        );
    }

    #[test]
    fn filename_sanitization_neutralizes_traversal_and_reserved_names() {
        assert_eq!(sanitize_filename("../../evil.exe").unwrap(), "evil.exe");
        assert_eq!(
            sanitize_filename(r"C:\dir\a:b*c?.txt").unwrap(),
            "a_b_c_.txt"
        );
        assert_eq!(sanitize_filename("CON.txt").unwrap(), "_CON.txt");
        assert_eq!(sanitize_filename("nul").unwrap(), "_nul");
        assert_eq!(sanitize_filename("lpt1.log").unwrap(), "_lpt1.log");
        assert_eq!(sanitize_filename("report.txt...  ").unwrap(), "report.txt");

        assert_eq!(
            sanitize_filename(".."),
            Err(ValidationError::InvalidFilename)
        );
        assert_eq!(
            sanitize_filename("."),
            Err(ValidationError::InvalidFilename)
        );
        assert_eq!(sanitize_filename(""), Err(ValidationError::InvalidFilename));
        assert_eq!(
            sanitize_filename("dir/"),
            Err(ValidationError::InvalidFilename)
        );
    }

    #[test]
    fn file_size_validation_bounds() {
        assert_eq!(validate_file_size(0), Err(ValidationError::InvalidFileSize));
        assert!(validate_file_size(1).is_ok());
        assert!(validate_file_size(MAX_FILE_TRANSFER_BYTES).is_ok());
        assert_eq!(
            validate_file_size(MAX_FILE_TRANSFER_BYTES + 1),
            Err(ValidationError::InvalidFileSize)
        );
    }

    #[test]
    fn identifier_and_received_body_sanitize_reject_malformed_inputs() {
        assert!(validate_identifier("peer-uuid-1234_ABCD").is_ok());
        assert_eq!(
            validate_identifier(&"a".repeat(MAX_IDENTIFIER_BYTES)),
            Ok(())
        );
        assert_eq!(
            validate_identifier(&"a".repeat(MAX_IDENTIFIER_BYTES + 1)),
            Err(ValidationError::InvalidIdentifier)
        );
        assert_eq!(
            validate_identifier(""),
            Err(ValidationError::InvalidIdentifier)
        );
        assert_eq!(
            validate_identifier("id with space"),
            Err(ValidationError::InvalidIdentifier)
        );
        assert_eq!(
            validate_identifier("id\x1b[31m"),
            Err(ValidationError::InvalidIdentifier)
        );

        let sanitized =
            validate_received_chat_body("受信\r\n本文\x00\x1b[31m\t保持\r末尾").unwrap();
        assert_eq!(sanitized, "受信\n本文[31m\t保持\n末尾");
        assert!(!sanitized.contains('\0'));
        assert!(!sanitized.contains('\x1b'));
        assert!(!sanitized.contains('\r'));
    }
}
