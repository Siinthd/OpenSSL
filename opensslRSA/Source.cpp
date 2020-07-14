
#include "RSAKey.h"


void main() {
	setlocale(LC_ALL, "Russian");
	andeme::RSAKey key;
	std::cout << key.getPublicKey() << std::endl;
	std::cout << key.getPrivate() << std::endl;
}