#ifndef CRYPT_RSA_H
#define CRYPT_RSA_H

#include "abstract_crypt_class.h"

class Crypt_RSA : public Crypt_Abs
{
private:
    QByteArray public_key;
    QByteArray private_key;
    bool keys_generated;

    QByteArray generate_key_pair();

public:
    Crypt_RSA();
    QByteArray crypt(const QString& data) override;
    QByteArray decrypt(const QByteArray& encryptedData) override;
    void set_key(const QString& data) override;

    void generate_keys();
    QByteArray get_public_key() const;
    QByteArray get_private_key() const;
    void set_public_key(const QByteArray& pubkey);
    void set_private_key(const QByteArray& privkey);
};

#endif
