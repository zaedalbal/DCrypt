#ifndef CRYPT_VERNAM_H
#define CRYPT_VERNAM_H

#include "abstract_alphabet_crypt_class.h"

class Crypt_Vernam : public Crypt_Alphabet_Abs
{
private:
    QString oneTimePad;
    AlphabetType currentAlphabet;
    bool removeSpaces;

    QChar encryptChar(QChar ch, QChar keyChar, const QString& alphabet) const;
    QChar decryptChar(QChar ch, QChar keyChar, const QString& alphabet) const;
    QString prepareKey(const QString& key, AlphabetType alphaType) const;

public:
    Crypt_Vernam();
    QByteArray crypt(const QString& data) override;
    QByteArray decrypt(const QByteArray& encryptedData) override;
    void set_key(const QString& data) override;
    void set_remove_spaces(bool remove);
    bool get_remove_spaces() const;
    QString check_one_time_pad() const;
};

#endif
