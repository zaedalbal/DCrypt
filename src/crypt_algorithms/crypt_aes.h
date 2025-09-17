#ifndef CRYPT_AES_H
#define CRYPT_AES_H

#include "abstract_crypt_class.h"

class Crypt_AES : public Crypt_Abs
{
private:
    QByteArray key;
    QByteArray iv;

    QByteArray generate_random_iv();

public:
    Crypt_AES();
    QByteArray crypt(const QString& data) override;
    QByteArray decrypt(const QByteArray& encryptedData) override;
    void set_key(const QString& data) override;
    QByteArray check_key();
    void set_iv(const QByteArray& custom_iv);
};

#endif
