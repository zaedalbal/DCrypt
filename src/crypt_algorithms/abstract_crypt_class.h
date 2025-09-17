#ifndef ABSTRACT_BASE_CRYPT_H
#define ABSTRACT_BASE_CRYPT_H

#include <QString>
#include <QByteArray>

class Crypt_Abs
{
private:
    QByteArray data_to_use;
public:
    virtual ~Crypt_Abs() = default;
    virtual QByteArray crypt(const QString& data) = 0;
    virtual QByteArray decrypt(const QByteArray& encrypteddata) = 0;
    virtual void set_key(const QString& data) = 0;
    void set_data(const QString& data)
    {
        data_to_use = data.toUtf8();
    }
    QByteArray check_data() const
    {
        return data_to_use;
    }
};

#endif
