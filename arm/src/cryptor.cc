#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "cryptor.h"
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>

#include <cryptopp/md5.h>
#include <cryptopp/files.h>

#include <stdlib.h> 
#include <time.h> 


std::string AESEncrypt(const std::string& plain, std::string& keyStr)
{
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = {0};
    CryptoPP::byte key[CryptoPP::AES::MAX_KEYLENGTH] = {0};
    std::string cipherEncoded, cipher;

    srand(time(NULL));
    for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; ++i) {
        iv[i] = rand() % 256;
    }
    memcpy(key, keyStr.data(), keyStr.length());

    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor(key, CryptoPP::AES::MAX_KEYLENGTH, iv);
        CryptoPP::StreamTransformationFilter stfEncryptor(encryptor,
            new CryptoPP::StringSink(cipher),
            CryptoPP::BlockPaddingSchemeDef::ZEROS_PADDING);
        stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plain.c_str()), plain.length() + 1);
        stfEncryptor.MessageEnd();
    } catch (std::exception e) {
        std::cout << e.what() << std::endl;
    }

    std::string cipherWithIV(reinterpret_cast<char*>(iv), sizeof(iv));
    cipherWithIV += cipher;

    //Will Stuck: CryptoPP::StringSource encoder(cipherWithIV, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(cipherEncoded)));
    CryptoPP::HexEncoder encoder;
    encoder.Attach(new CryptoPP::StringSink(cipherEncoded));
    encoder.Put(reinterpret_cast<const unsigned char*>(cipherWithIV.c_str()), cipherWithIV.length());
    encoder.MessageEnd();

    return cipherEncoded;
}

std::string AESDecrypt(std::string& cipher, std::string& keyStr)
{
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = {0};
    CryptoPP::byte key[CryptoPP::AES::MAX_KEYLENGTH] = {0};
    std::string cipherDecoded, cipherWithoutIV, decrypted;

    memcpy(key, keyStr.data(), keyStr.length());

    //Will Stuck: CryptoPP::StringSource decoder(cipher, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(cipherDecoded)));
    CryptoPP::HexDecoder decoder;
    decoder.Attach(new CryptoPP::StringSink(cipherDecoded));
    decoder.Put(reinterpret_cast<const unsigned char*>(cipher.c_str()), cipher.length());
    decoder.MessageEnd();

    memcpy(iv, cipherDecoded.data(), 16);
    cipherWithoutIV = cipherDecoded.substr(16);

    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor(key, CryptoPP::AES::MAX_KEYLENGTH, iv);
        CryptoPP::StreamTransformationFilter stfDecryptor(decryptor,
            new CryptoPP::StringSink(decrypted),
            CryptoPP::BlockPaddingSchemeDef::ZEROS_PADDING);
        stfDecryptor.Put(reinterpret_cast<const unsigned char*>(cipherWithoutIV.c_str()), cipherWithoutIV.length());
        stfDecryptor.MessageEnd();
    } catch (std::exception e) {
        std::cout << e.what() << std::endl;
    }

    return decrypted;
}

std::string MD5Encrypt(const std::string& path)
{
    std::string MD5Hash;

    try {
        CryptoPP::Weak1::MD5 MD;
        CryptoPP::FileSource(path.c_str(), true,
            new CryptoPP::HashFilter(MD,
            new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(MD5Hash))));
    } catch (std::exception e) {
        std::cout << e.what() << std::endl;
    }

    return MD5Hash;
}
