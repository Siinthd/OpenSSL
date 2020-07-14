#include "RSAKey.h"

namespace andeme {
	RSAKey::RSAKey() 
	{
	}

	RSAKey::~RSAKey()
	{
	}

	std::string RSAKey::getPublicKey()
	{
		RSA* pKeyPair = nullptr;
		BIO* bio;
		bio = BIO_new(BIO_s_mem());

		const EVP_CIPHER* cipher = EVP_get_cipherbyname("aes-256-cbc");


		if (cipher == NULL)
			OpenSSL_add_all_algorithms();

		/* Generate RSA  */
		if (pKeyPair != nullptr)
			RSA_free(pKeyPair);
		pKeyPair = RSA_generate_key(RSA_KEYLENGTH, RSA_E, NULL, NULL);


		PEM_write_bio_RSAPublicKey(bio, pKeyPair);
		size_t length = BIO_ctrl_pending(bio);

		std::string pstr;
		void* buf = malloc(length);

		BIO_read(bio, buf, length);

		std::string pem = std::string(reinterpret_cast<const char*>(buf), length);
	
		return pem;
	}
	std::string RSAKey::getPrivate()
	{
		RSA* pKeyPair = nullptr;
		BIO* bio;
		bio = BIO_new(BIO_s_mem());
		pKeyPair = RSA_generate_key(RSA_KEYLENGTH, RSA_E, NULL, NULL);

		int ret = PEM_write_bio_RSAPrivateKey(bio, pKeyPair, nullptr, nullptr, 0, nullptr, nullptr);


		size_t length = BIO_ctrl_pending(bio);

		std::string pstr;
		void* buf = malloc(length);

		BIO_read(bio, buf, length);

		std::string pem = std::string(reinterpret_cast<const char*>(buf), length);

		return pem;
	}
}