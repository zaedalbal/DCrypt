#ifndef CRYPT_CAESAR_H
#define CRYPT_CAESAR_H

#include "abstract_alphabet_crypt_class.h"

class Crypt_Caesar : public Crypt_Alphabet_Abs
{
private:
    int shift;
    AlphabetType currentAlphabet;

    QChar shiftChar(QChar ch, int shift_value, const QString& alphabet) const;

public:
    Crypt_Caesar();
    QByteArray crypt(const QString& data) override;
    QByteArray decrypt(const QByteArray& encryptedData) override;
    void set_key(const QString& data) override;
    int check_shift() const;
};

#endif
