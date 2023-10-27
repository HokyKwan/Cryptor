/**********************************
 *
 *       AES Cryptor For QT
 *
 * Author: HokyKwan
 * date  : 10/27 2023
 *
***********************************/
#ifndef CRYPTOR_H
#define CRYPTOR_H

#include <QByteArray>

class Cryptor
{
public:
    Cryptor(const QByteArray& key);
    ~Cryptor() = default;

    QByteArray Encrypt(const QByteArray& plain);
    QByteArray Decrypt(const QByteArray& cipher);

private:
    QByteArray key_;
};

#endif // CRYPTOR_H
