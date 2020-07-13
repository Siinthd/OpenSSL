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

		
		EVP_PKEY* evpkey = EVP_PKEY_new();
		EVP_PKEY_set1_RSA(evpkey, pKeyPair); return pKeyPair;
	}
}