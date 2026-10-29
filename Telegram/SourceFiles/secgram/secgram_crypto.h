/*
This file is part of SecGram, a security-focused Telegram Desktop fork.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

// AES-256-GCM for the local SecGram logs. The key is derived from the
// tdesktop local key, which itself is protected by the local passcode.
namespace SecGram {

extern const char kOptionEncryptLogs[];

[[nodiscard]] bool EncryptLogsEnabled();

// "enc:" + base64(nonce | ciphertext | tag), or the input when disabled
// or the key is not available.
[[nodiscard]] QByteArray SealLine(const QByteArray &plain);

// Accepts both sealed and plain (old) lines.
[[nodiscard]] QByteArray OpenLine(const QByteArray &line);

} // namespace SecGram
