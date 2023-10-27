/**********************************
 *
 *       AES Cryptor For QT
 *
 * Author: HokyKwan
 * date  : 10/27 2023
 *
***********************************/
#include "Cryptor.h"
#include <QRandomGenerator>
#include "QAESEncryption.h"


Cryptor::Cryptor(const QByteArray& key) : key_(key)
{
}

QByteArray Cryptor::Encrypt(const QByteArray& plain)
{
    QByteArray iv, cipherWithIV;

    for (size_t i = 0; i < 16; ++i) {
        iv.append(static_cast<unsigned char>(QRandomGenerator::global()->bounded(256)));
    }

    QAESEncryption encryptor(QAESEncryption::AES_256, QAESEncryption::CBC);
    QByteArray cipher = encryptor.encode(plain, key_, iv);
    cipherWithIV.append(iv);
    cipherWithIV.append(cipher);
    QByteArray cipherHexed = cipherWithIV.toHex();

    return cipherHexed;
}

QByteArray Cryptor::Decrypt(const QByteArray& cipherHexed)
{
    QAESEncryption decryptor(QAESEncryption::AES_256, QAESEncryption::CBC);
    QByteArray cipherWithIV = QByteArray::fromHex(cipherHexed);
    QByteArray iv = cipherWithIV.left(16);
    QByteArray cipher = cipherWithIV.mid(16, cipherWithIV.size());
    QByteArray decrypt = decryptor.decode(cipher, key_, iv);

    return QAESEncryption::RemovePadding(decrypt);
}
