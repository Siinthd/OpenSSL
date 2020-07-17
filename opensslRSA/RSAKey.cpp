#include "RSAKey.h"

namespace andeme {
	RSAKey::RSAKey() : bio(BIO_new(BIO_s_mem())),
		pKeyPair(RSA_new())
	{
		BIGNUM* e = BN_new();
		BN_set_word(e, RSA_F4);
		RSA_generate_key_ex(pKeyPair, RSA_KEYLENGTH, e, 0);
	}

	RSAKey::~RSAKey()
	{
		if (pKeyPair != nullptr)
			RSA_free(pKeyPair);
		if (bio != nullptr)
			BIO_free(bio);
	}

	std::string RSAKey::getPublicKey()
	{
		PEM_write_bio_RSAPublicKey(bio, pKeyPair);
		size_t length = BIO_ctrl_pending(bio);

		std::string pstr;
		pstr.resize(length);
		BIO_read(bio, pstr.data(), length);

		std::string pem = std::string(reinterpret_cast<const char*>(pstr.data()), length);
		return pem;
	}
	std::string RSAKey::getPrivate()
	{
		int ret = PEM_write_bio_RSAPrivateKey(bio, pKeyPair, nullptr, nullptr, 0, nullptr, nullptr);

		size_t length = BIO_ctrl_pending(bio);

		std::string pstr;
		pstr.resize(length);
		BIO_read(bio, pstr.data(), length);

		std::string pem = std::string(reinterpret_cast<const char*>(pstr.data()), length);
		return pem;
	}

	std::pair<std::string, std::string> RSAKey::generate()
	{
		return { getPublicKey(),getPrivate() };
	}
}