#include "crypt_caesar.h"

Crypt_Caesar::Crypt_Caesar() : Crypt_Alphabet_Abs()
{
    shift = 3;
    currentAlphabet = AlphabetType::NONE;
}

void Crypt_Caesar::set_key(const QString& data)
{
    bool ok;
    int value = data.toInt(&ok);
    if(ok)
    {
        shift = value;
    }
    else
    {
        shift = 3;
    }
}

int Crypt_Caesar::check_shift() const
{
    return shift;
}

QChar Crypt_Caesar::shiftChar(QChar ch, int shift_value, const QString& alphabet) const
{
    if(!ch.isLetter())
        return ch;

    QChar upper = ch.toUpper();
    int index = alphabet.indexOf(upper);

    if(index == -1)
        return ch;

    int newIndex = (index + shift_value) % alphabet.length();
    if(newIndex < 0)
        newIndex += alphabet.length();

    QChar result = alphabet[newIndex];
    return ch.isLower() ? result.toLower() : result;
}

QByteArray Crypt_Caesar::crypt(const QString& data)
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

    QString result;
    for(const QChar& ch : data)
    {
        result += shiftChar(ch, shift, alphabet);
    }

    return result.toUtf8();
}

QByteArray Crypt_Caesar::decrypt(const QByteArray& encryptedData)
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

    QString result;
    for(const QChar& ch : encrypted)
    {
        result += shiftChar(ch, -shift, alphabet);
    }

    return result.toUtf8();
}
