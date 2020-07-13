#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <conio.h>
#include <io.h>
#include <fcntl.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "RSAKey.h"

using namespace std;
void GenKeys(char secret[]);
void Enc();
void Dec(char secret[]);
void GenKeysMenu();
void EncryptMenu();
void DecryptMenu();

void main() {
	setlocale(LC_ALL, "Russian");
	RSAKey key;
}

void GenKeys(char secret[]) {
	/* ��������� �� ��������� ��� �������� ������ */
	RSA * rsa = NULL;
	unsigned long bits = 1024; /* ����� ����� � ����� */
	FILE * privKey_file = NULL, *pubKey_file = NULL;
	/* �������� ��������� ���������� */
	const EVP_CIPHER *cipher = NULL;
	/*������� ����� ������*/
	privKey_file = fopen("\private.key", "wb");
	pubKey_file = fopen("\public.key", "wb");
	/* ���������� ����� */
	rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
	/* ��������� �������� ��������� ���������� */
	cipher = EVP_get_cipherbyname("bf-ofb");
	/* �������� �� ��������� rsa �������� � ��������� ����� � ��������� � ������.
	* ��������� ���� ������� � ������� ��������� �����
	*/
	PEM_write_RSAPrivateKey(privKey_file, rsa, cipher, NULL, 0, NULL, secret);
	PEM_write_RSAPublicKey(pubKey_file, rsa);
	/* ����������� ������, ���������� ��� ��������� rsa */
	RSA_free(rsa);
	fclose(privKey_file);
	fclose(pubKey_file);
	cout << "����� ������������� � �������� � ����� � ����������� ������" << endl;
}

void Encrypt() {
	/* ��������� ��� �������� ��������� ����� */
	RSA * pubKey = NULL;
	FILE * pubKey_file = NULL;
	unsigned char *ctext, *ptext;
	int inlen, outlen;
	/* ��������� �������� ���� */
	pubKey_file = fopen("\public.key", "rb");
	pubKey = PEM_read_RSAPublicKey(pubKey_file, NULL, NULL, NULL);
	fclose(pubKey_file);

	/* ���������� ����� ����� */
	int key_size = RSA_size(pubKey);
	ctext = (unsigned char *)malloc(key_size);
	ptext = (unsigned char *)malloc(key_size);
	OpenSSL_add_all_algorithms();

	int out = _open("rsa.file", O_CREAT | O_TRUNC | O_RDWR, 0600);
	int in = _open("in.txt", O_RDWR);
	/* ������� ���������� �������� ����� */
	while (1) {
		inlen = _read(in, ptext, key_size - 11);
		if (inlen <= 0) break;
		outlen = RSA_public_encrypt(inlen, ptext, ctext, pubKey, RSA_PKCS1_PADDING);
		if (outlen != RSA_size(pubKey)) exit(-1);
		_write(out, ctext, outlen);
	}
	cout << "���������� ����� in.txt ���� ����������� � �������� � ���� rsa.file" << endl;
}

void Decrypt(char secret[]) {
	RSA * privKey = NULL;
	FILE * privKey_file;
	unsigned char *ptext, *ctext;
	int inlen, outlen;

	/* ��������� �������� ���� � ��������� ��������� ���� */
	OpenSSL_add_all_algorithms();
	privKey_file = fopen("private.key", "rb");
	privKey = PEM_read_RSAPrivateKey(privKey_file, NULL, NULL, secret);

	/* ���������� ������ ����� */
	int key_size = RSA_size(privKey);
	ptext = (unsigned char *)malloc(key_size);
	ctext = (unsigned char *)malloc(key_size);

	int out = _open("out.txt", O_CREAT | O_TRUNC | O_RDWR, 0600);
	int in = _open("rsa.file", O_RDWR);

	/* ��������� ���� */
	while (1) {
		inlen = _read(in, ctext, key_size);
		if (inlen <= 0) break;
		outlen = RSA_private_decrypt(inlen, ctext, ptext, privKey, RSA_PKCS1_PADDING);
		if (outlen < 0) exit(0);
		_write(out, ptext, outlen);
	}
	cout << "���������� ����� rsa.file ���� ����������� � �������� � ���� out.txt" << endl;

}
void GenKeysMenu() {
	char secret[] = "";
	system("cls");
	cout << "-------------- ���������� RSA --------------" << endl << endl;
	cout << "������� ��������� ����� ��� ��������� �����: ";
	cin >> secret;
	GenKeys(secret);
	cout << "������� ����� ������ ��� �������� � ����...";
	_getch();
}
void EncryptMenu() {
	system("cls");
	cout << "-------------- ���������� RSA --------------" << endl << endl;
	Encrypt();
	cout << "������� ����� ������ ��� �������� � ����...";
	_getch();
}
void DecryptMenu() {
	char secret[] = "";
	system("cls");
	cout << "-------------- ���������� RSA --------------" << endl << endl;
	cout << "������� ��������� ����� ��� ��������� �����: ";
	cin >> secret;
	Decrypt(secret);
	cout << "������� ����� ������ ��� �������� � ����...";
	_getch();
}