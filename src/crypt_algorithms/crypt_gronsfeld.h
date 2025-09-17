#ifndef CRYPT_GRONSFELD_H
#define CRYPT_GRONSFELD_H

#include "abstract_alphabet_crypt_class.h"

class Crypt_Gronsfeld : public Crypt_Alphabet_Abs
{
private:
    QString numericKey;
    AlphabetType currentAlphabet;
    bool removeSpaces;

    QChar encryptChar(QChar ch, int shift, const QString& alphabet) const;
    QChar decryptChar(QChar ch, int shift, const QString& alphabet) const;
    QString prepareNumericKey(const QString& key) const;

public:
    Crypt_Gronsfeld();
    QByteArray crypt(const QString& data) override;
    QByteArray decrypt(const QByteArray& encryptedData) override;
    void set_key(const QString& data) override;
    void set_remove_spaces(bool remove);
    bool get_remove_spaces() const;
    QString check_numeric_key() const;
};

#endif
