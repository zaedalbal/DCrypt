#ifndef CRYPT_VIGENERE_H
#define CRYPT_VIGENERE_H

#include "abstract_alphabet_crypt_class.h"

class Crypt_Vigenere : public Crypt_Alphabet_Abs
{
private:
    QString keyword;
    AlphabetType currentAlphabet;

    QChar encryptChar(QChar ch, QChar key_char, const QString& alphabet) const;
    QChar decryptChar(QChar ch, QChar key_char, const QString& alphabet) const;
    QString prepareKeyword(const QString& key, AlphabetType alphaType) const;

public:
    Crypt_Vigenere();
    QByteArray crypt(const QString& data) override;
    QByteArray decrypt(const QByteArray& encryptedData) override;
    void set_key(const QString& data) override;
    QString check_keyword() const;
};

#endif
