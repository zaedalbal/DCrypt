#ifndef CRYPT_DES_H
#define CRYPT_DES_H

#include "abstract_crypt_class.h"

class Crypt_Des : public Crypt_Abs
{
private:
    QByteArray key;
public:
    Crypt_Des();
    QByteArray crypt(const QString& data) override;
    QByteArray decrypt(const QByteArray& encryptedData) override;
    void set_key(const QString& data) override;
    QByteArray check_key();
};

#endif
