/*
This file is part of SecGram, a security-focused Telegram Desktop fork.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "secgram/secgram_crypto.h"

#include "base/options.h"
#include "core/application.h"
#include "main/main_domain.h"
#include "mtproto/mtproto_auth_key.h"
#include "storage/storage_domain.h"

#include <QtCore/QCryptographicHash>

#include <openssl/evp.h>
#include <openssl/rand.h>

namespace SecGram {
namespace {

constexpr auto kNonceSize = 12;
constexpr auto kTagSize = 16;

base::options::toggle EncryptLogs({
	.id = kOptionEncryptLogs,
	.name = "Шифровать журналы SecGram",
	.description = "Журнал удалённых сообщений и совпадений наблюдения "
		"шифруются AES-256-GCM ключом, защищённым локальным код-паролем.",
	.defaultValue = true,
});

[[nodiscard]] QByteArray LogKey() {
	if (!Core::IsAppLaunched()) {
		return QByteArray();
	}
	const auto &key = Core::App().domain().local().localKey();
	if (!key) {
		return QByteArray();
	}
	const auto data = key->data();
	auto hash = QCryptographicHash(QCryptographicHash::Sha256);
	hash.addData(QByteArrayView(
		reinterpret_cast<const char*>(data.data()),
		qsizetype(data.size())));
	hash.addData(QByteArrayView("secgram-log-v1"));
	return hash.result();
}

} // namespace

const char kOptionEncryptLogs[] = "secgram-encrypt-logs";

bool EncryptLogsEnabled() {
	return EncryptLogs.value();
}

QByteArray SealLine(const QByteArray &plain) {
	if (!EncryptLogs.value()) {
		return plain;
	}
	const auto key = LogKey();
	if (key.size() != 32) {
		return plain;
	}
	auto nonce = QByteArray(kNonceSize, Qt::Uninitialized);
	RAND_bytes(reinterpret_cast<unsigned char*>(nonce.data()), kNonceSize);
	auto cipher = QByteArray(plain.size(), Qt::Uninitialized);
	auto tag = QByteArray(kTagSize, Qt::Uninitialized);
	unsigned char final[32] = { 0 }; // GCM writes nothing here.
	const auto ctx = EVP_CIPHER_CTX_new();
	auto length = 0;
	const auto ok = ctx
		&& EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)
		&& EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kNonceSize, nullptr)
		&& EVP_EncryptInit_ex(
			ctx,
			nullptr,
			nullptr,
			reinterpret_cast<const unsigned char*>(key.constData()),
			reinterpret_cast<const unsigned char*>(nonce.constData()))
		&& EVP_EncryptUpdate(
			ctx,
			reinterpret_cast<unsigned char*>(cipher.data()),
			&length,
			reinterpret_cast<const unsigned char*>(plain.constData()),
			int(plain.size()))
		&& EVP_EncryptFinal_ex(ctx, final, &length)
		&& EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagSize, tag.data());
	EVP_CIPHER_CTX_free(ctx);
	return ok
		? ("enc:" + (nonce + cipher + tag).toBase64())
		: plain;
}

QByteArray OpenLine(const QByteArray &line) {
	const auto trimmed = line.trimmed();
	if (!trimmed.startsWith("enc:")) {
		return trimmed;
	}
	const auto key = LogKey();
	const auto raw = QByteArray::fromBase64(trimmed.mid(4));
	if (key.size() != 32 || raw.size() < kNonceSize + kTagSize) {
		return QByteArray();
	}
	const auto nonce = raw.left(kNonceSize);
	const auto tag = raw.right(kTagSize);
	const auto cipher = raw.mid(kNonceSize, raw.size() - kNonceSize - kTagSize);
	auto plain = QByteArray(cipher.size(), Qt::Uninitialized);
	auto tagCopy = tag;
	unsigned char final[32] = { 0 };
	const auto ctx = EVP_CIPHER_CTX_new();
	auto length = 0;
	const auto ok = ctx
		&& EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)
		&& EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kNonceSize, nullptr)
		&& EVP_DecryptInit_ex(
			ctx,
			nullptr,
			nullptr,
			reinterpret_cast<const unsigned char*>(key.constData()),
			reinterpret_cast<const unsigned char*>(nonce.constData()))
		&& EVP_DecryptUpdate(
			ctx,
			reinterpret_cast<unsigned char*>(plain.data()),
			&length,
			reinterpret_cast<const unsigned char*>(cipher.constData()),
			int(cipher.size()))
		&& EVP_CIPHER_CTX_ctrl(
			ctx,
			EVP_CTRL_GCM_SET_TAG,
			kTagSize,
			tagCopy.data())
		&& (EVP_DecryptFinal_ex(ctx, final, &length) > 0);
	EVP_CIPHER_CTX_free(ctx);
	return ok ? plain : QByteArray();
}

} // namespace SecGram
