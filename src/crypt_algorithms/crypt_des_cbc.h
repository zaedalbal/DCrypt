#ifndef CRYPT_DES_CBC_H
#define CRYPT_DES_CBC_H

#include "abstract_crypt_class.h"
#include <QByteArray>

class Crypt_Des_CBC : public Crypt_Abs
{
private:
    QByteArray key;
    QByteArray iv;

    QByteArray generate_random_iv();

    QByteArray extract_iv_from_data(const QByteArray& data);

    QByteArray remove_iv_from_data(const QByteArray& data);

public:
    Crypt_Des_CBC();
    QByteArray crypt(const QString& data) override;
    QByteArray decrypt(const QByteArray& encryptedData) override;
    void set_key(const QString& data) override;
    QByteArray check_key();

    void set_iv(const QByteArray& custom_iv);
    QByteArray check_iv() const;
};

#endif
