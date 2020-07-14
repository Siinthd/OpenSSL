#include "RSAKey.h"

namespace andeme {
	RSAKey::RSAKey() 
	{
	}

	RSAKey::~RSAKey()
	{
	}

	RSA* RSAKey::getPublicKey() 
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

		void *buf = static_cast<void*>(new std::string);

		//void* buf = nullptr;
		BIO_read(bio, buf, length);

		std::string *pstr = static_cast<std::string *>(buf);
		std::cout << pstr;
		return pKeyPair;
	}
}