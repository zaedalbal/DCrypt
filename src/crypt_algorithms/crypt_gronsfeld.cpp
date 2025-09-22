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

    AlphabetType alphaType = detectAlphabet(data);
    if(alphaType == AlphabetType::MIXED)
        return QByteArray("[ОШИБКА: СМЕШАННЫЕ АЛФАВИТЫ НЕ ПОДДЕРЖИВАЮТСЯ]");

    if(alphaType == AlphabetType::NONE)
        return QByteArray("[ОШИБКА: НЕ НАЙДЕНЫ БУКВЫ ДЛЯ ШИФРОВАНИЯ]");

    // Фильтруем текст - удаляем все лишние символы
    QString filteredData = filterText(data, alphaType, removeSpaces);

    if(filteredData.isEmpty())
        return QByteArray("[ОШИБКА: ПОСЛЕ ФИЛЬТРАЦИИ НЕ ОСТАЛОСЬ СИМВОЛОВ]");

    currentAlphabet = alphaType;
    QString alphabet = (alphaType == AlphabetType::RUSSIAN) ?
                           russianAlphabet.toLower() + "0123456789" :
                           englishAlphabet.toLower() + "0123456789";

    QString result;
    for(int i = 0; i < filteredData.length(); ++i)
    {
        int shift = numericKey[i % numericKey.length()].digitValue();
        result += encryptChar(filteredData[i], shift, alphabet);
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

    AlphabetType alphaType = detectAlphabet(encrypted);
    if(alphaType == AlphabetType::MIXED)
        return QByteArray("[ОШИБКА: СМЕШАННЫЕ АЛФАВИТЫ НЕ ПОДДЕРЖИВАЮТСЯ]");

    if(alphaType == AlphabetType::NONE)
        return QByteArray("[ОШИБКА: НЕ НАЙДЕНЫ БУКВЫ ДЛЯ РАСШИФРОВКИ]");

    QString alphabet = (alphaType == AlphabetType::RUSSIAN) ?
                           russianAlphabet.toLower() + "0123456789" :
                           englishAlphabet.toLower() + "0123456789";

    QString result;
    for(int i = 0; i < encrypted.length(); ++i)
    {
        int shift = numericKey[i % numericKey.length()].digitValue();
        result += decryptChar(encrypted[i], shift, alphabet);
    }

    return result.toUtf8();
}
