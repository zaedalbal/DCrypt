#include "crypt_vigenere.h"

Crypt_Vigenere::Crypt_Vigenere() : Crypt_Alphabet_Abs()
{
    keyword = "КЛЮЧ";
    currentAlphabet = AlphabetType::NONE;
}

void Crypt_Vigenere::set_key(const QString& data)
{
    if(data.isEmpty())
    {
        keyword = "КЛЮЧ";
    }
    else
    {
        keyword = data.toUpper();
    }
}

QString Crypt_Vigenere::check_keyword() const
{
    return keyword;
}

QString Crypt_Vigenere::prepareKeyword(const QString& key, AlphabetType alphaType) const
{
    QString prepared;
    QString alphabet = (alphaType == AlphabetType::RUSSIAN) ? russianAlphabet : englishAlphabet;

    for(const QChar& ch : key)
    {
        QChar upper = ch.toUpper();
        if(alphabet.contains(upper))
        {
            prepared += upper;
        }
    }

    if(prepared.isEmpty())
    {
        prepared = (alphaType == AlphabetType::RUSSIAN) ? "КЛЮЧ" : "KEY";
    }

    return prepared;
}

QChar Crypt_Vigenere::encryptChar(QChar ch, QChar key_char, const QString& alphabet) const
{
    if(!ch.isLetter())
        return ch;

    QChar upper = ch.toUpper();
    int textIndex = alphabet.indexOf(upper);
    int keyIndex = alphabet.indexOf(key_char);

    if(textIndex == -1 || keyIndex == -1)
        return ch;

    int encryptedIndex = (textIndex + keyIndex) % alphabet.length();
    QChar result = alphabet[encryptedIndex];

    return ch.isLower() ? result.toLower() : result;
}

QChar Crypt_Vigenere::decryptChar(QChar ch, QChar key_char, const QString& alphabet) const
{
    if(!ch.isLetter())
        return ch;

    QChar upper = ch.toUpper();
    int textIndex = alphabet.indexOf(upper);
    int keyIndex = alphabet.indexOf(key_char);

    if(textIndex == -1 || keyIndex == -1)
        return ch;

    int decryptedIndex = (textIndex - keyIndex + alphabet.length()) % alphabet.length();
    QChar result = alphabet[decryptedIndex];

    return ch.isLower() ? result.toLower() : result;
}

QByteArray Crypt_Vigenere::crypt(const QString& data)
{
    if(data.isEmpty())
        return QByteArray("[ОШИБКА: ПУСТЫЕ ВХОДНЫЕ ДАННЫЕ]");

    AlphabetType alphaType = detectAlphabet(data);
    if(alphaType == AlphabetType::MIXED)
        return QByteArray("[ОШИБКА: СМЕШАННЫЕ АЛФАВИТЫ НЕ ПОДДЕРЖИВАЮТСЯ]");

    if(alphaType == AlphabetType::NONE)
        return QByteArray("[ОШИБКА: НЕ НАЙДЕНЫ БУКВЫ ДЛЯ ШИФРОВАНИЯ]");

    currentAlphabet = alphaType;
    QString alphabet = (alphaType == AlphabetType::RUSSIAN) ? russianAlphabet : englishAlphabet;
    QString prepared_key = prepareKeyword(keyword, alphaType);

    QString result;
    int keyIndex = 0;

    for(const QChar& ch : data)
    {
        if(ch.isLetter() && alphabet.contains(ch.toUpper()))
        {
            QChar key_char = prepared_key[keyIndex % prepared_key.length()];
            result += encryptChar(ch, key_char, alphabet);
            keyIndex++;
        }
        else
        {
            result += ch;
        }
    }

    return result.toUtf8();
}

QByteArray Crypt_Vigenere::decrypt(const QByteArray& encryptedData)
{
    if(encryptedData.startsWith("[ОШИБКА:"))
        return encryptedData;

    QString encrypted = QString::fromUtf8(encryptedData);
    if(encrypted.isEmpty())
        return QByteArray("[ОШИБКА: ПУСТЫЕ ЗАШИФРОВАННЫЕ ДАННЫЕ]");

    AlphabetType alphaType = detectAlphabet(encrypted);
    if(alphaType == AlphabetType::MIXED)
        return QByteArray("[ОШИБКА: СМЕШАННЫЕ АЛФАВИТЫ НЕ ПОДДЕРЖИВАЮТСЯ]");

    if(alphaType == AlphabetType::NONE)
        return QByteArray("[ОШИБКА: НЕ НАЙДЕНЫ БУКВЫ ДЛЯ РАСШИФРОВКИ]");

    QString alphabet = (alphaType == AlphabetType::RUSSIAN) ? russianAlphabet : englishAlphabet;
    QString prepared_key = prepareKeyword(keyword, alphaType);

    QString result;
    int keyIndex = 0;

    for(const QChar& ch : encrypted)
    {
        if(ch.isLetter() && alphabet.contains(ch.toUpper()))
        {
            QChar key_char = prepared_key[keyIndex % prepared_key.length()];
            result += decryptChar(ch, key_char, alphabet);
            keyIndex++;
        }
        else
        {
            result += ch;
        }
    }

    return result.toUtf8();
}
