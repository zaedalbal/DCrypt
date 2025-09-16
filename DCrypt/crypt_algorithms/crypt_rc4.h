#ifndef CRYPT_RC4_H
#define CRYPT_RC4_H

#include "abstract_crypt_class.h"

class Crypt_RC4 : public Crypt_Abs
{
private:
    QByteArray key;

public:
    Crypt_RC4();
    QByteArray crypt(const QString& data) override;
    QByteArray decrypt(const QByteArray& encryptedData) override;
    void set_key(const QString& data) override;
    QByteArray check_key();
};

#endif
