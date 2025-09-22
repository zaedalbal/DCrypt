#ifndef ABSTRACT_ALPHABET_CRYPT_H
#define ABSTRACT_ALPHABET_CRYPT_H

#include <QString>
#include <QByteArray>

enum class AlphabetType
{
    NONE,
    RUSSIAN,
    ENGLISH,
    MIXED
};

class Crypt_Alphabet_Abs
{
private:
    QString data_to_use;

protected:
    AlphabetType detectAlphabet(const QString& text) const; // определение типа алфавита
    bool isRussianChar(QChar ch) const;
    bool isEnglishChar(QChar ch) const;
    QString filterText(const QString& text, AlphabetType alphaType, bool removeSpaces = false) const; // новый метод фильтрации
    QString russianAlphabet = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
    QString englishAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

public:
    virtual ~Crypt_Alphabet_Abs() = default;
    virtual QByteArray crypt(const QString& data) = 0;
    virtual QByteArray decrypt(const QByteArray& encrypteddata) = 0;
    virtual void set_key(const QString& data) = 0;

    void set_data(const QString& data)
    {
        data_to_use = data;
    }

    QString check_data() const
    {
        return data_to_use;
    }
};

#endif
