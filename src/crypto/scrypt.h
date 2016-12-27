#ifndef SCRYPT_H
#define SCRYPT_H
#include <stdlib.h>
#include <stdint.h>
#include <string>

void scrypt(std::string strPassphrase, std::string strSalt, char *output, unsigned int N, unsigned int r, unsigned int p, unsigned int dkLen);

#endif