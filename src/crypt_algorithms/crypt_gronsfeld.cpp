#include "crypt_gronsfeld.h"

Crypt_Gronsfeld::Crypt_Gronsfeld() : Crypt_Alphabet_Abs()
{
    numericKey = "1234";
    currentAlphabet = AlphabetType::NONE;
    removeSpaces = false;
}

void Crypt_Gronsfeld::set_key(const QString& data)
{
    QString prepared = prepareNumericKey(data);
    if(prepared.isEmpty())
    {
        numericKey = "1234";
    }
    else
    {
        numericKey = prepared;
    }
}

void Crypt_Gronsfeld::set_remove_spaces(bool remove)
{
    removeSpaces = remove;
}

bool Crypt_Gronsfeld::get_remove_spaces() const
{
    return removeSpaces;
}

QString Crypt_Gronsfeld::check_numeric_key() const
{
    return numericKey;
}

QString Crypt_Gronsfeld::prepareNumericKey(const QString& key) const
{
    QString prepared;
    for(const QChar& ch : key)
    {
        if(ch.isDigit())
        {
            prepared += ch;
        }
    }
    return prepared;
}

QChar Crypt_Gronsfeld::encryptChar(QChar ch, int shift, const QString& alphabet) const
{
    if(!alphabet.contains(ch))
        return ch;

    int index = alphabet.indexOf(ch);
    int encryptedIndex = (index + shift) % alphabet.length();
    return alphabet[encryptedIndex];
}

QChar Crypt_Gronsfeld::decryptChar(QChar ch, int shift, const QString& alphabet) const
{
    if(!alphabet.contains(ch))
        return ch;

    int index = alphabet.indexOf(ch);
    int decryptedIndex = (index - shift + alphabet.length()) % alphabet.length();
    return alphabet[decryptedIndex];
}

QByteArray Crypt_Gronsfeld::crypt(const QString& data)
{
    if(data.isEmpty())
        return QByteArray("[ОШИБКА: ПУСТЫЕ ВХОДНЫЕ ДАННЫЕ]");

    QString processedData = data.toLower();

    AlphabetType alphaType = detectAlphabet(processedData);
    if(alphaType == AlphabetType::MIXED)
        return QByteArray("[ОШИБКА: СМЕШАННЫЕ АЛФАВИТЫ НЕ ПОДДЕРЖИВАЮТСЯ]");

    if(alphaType == AlphabetType::NONE)
        return QByteArray("[ОШИБКА: НЕ НАЙДЕНЫ БУКВЫ ДЛЯ ШИФРОВАНИЯ]");

    currentAlphabet = alphaType;
    QString alphabet = (alphaType == AlphabetType::RUSSIAN) ?
                           russianAlphabet + "0123456789" :
                           englishAlphabet + "0123456789";
    alphabet = alphabet.toLower();

    QString result;
    int keyIndex = 0;

    for(const QChar& ch : processedData)
    {
        if(ch == ' ' && removeSpaces)
        {
            continue;
        }

        if(alphabet.contains(ch))
        {
            int shift = numericKey[keyIndex % numericKey.length()].digitValue();
            result += encryptChar(ch, shift, alphabet);
            keyIndex++;
        }
        else
        {
            if(!removeSpaces || ch != ' ')
            {
                result += ch;
            }
        }
    }

    return result.toUtf8();
}

QByteArray Crypt_Gronsfeld::decrypt(const QByteArray& encryptedData)
{
    if(encryptedData.startsWith("[ОШИБКА:"))
        return encryptedData;

    QString encrypted = QString::fromUtf8(encryptedData);
    if(encrypted.isEmpty())
        return QByteArray("[ОШИБКА: ПУСТЫЕ ЗАШИФРОВАННЫЕ ДАННЫЕ]");

    encrypted = encrypted.toLower();

    AlphabetType alphaType = detectAlphabet(encrypted);
    if(alphaType == AlphabetType::MIXED)
        return QByteArray("[ОШИБКА: СМЕШАННЫЕ АЛФАВИТЫ НЕ ПОДДЕРЖИВАЮТСЯ]");

    if(alphaType == AlphabetType::NONE)
        return QByteArray("[ОШИБКА: НЕ НАЙДЕНЫ БУКВЫ ДЛЯ РАСШИФРОВКИ]");

    QString alphabet = (alphaType == AlphabetType::RUSSIAN) ?
                           russianAlphabet + "0123456789" :
                           englishAlphabet + "0123456789";
    alphabet = alphabet.toLower();

    QString result;
    int keyIndex = 0;

    for(const QChar& ch : encrypted)
    {
        if(alphabet.contains(ch))
        {
            int shift = numericKey[keyIndex % numericKey.length()].digitValue();
            result += decryptChar(ch, shift, alphabet);
            keyIndex++;
        }
        else
        {
            result += ch;
        }
    }

    return result.toUtf8();
}
