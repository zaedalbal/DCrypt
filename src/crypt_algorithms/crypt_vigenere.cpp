#include "crypt_vigenere.h"

Crypt_Vigenere::Crypt_Vigenere() : Crypt_Alphabet_Abs()
{
    keyword = "ключ";
    currentAlphabet = AlphabetType::NONE;
    removeSpaces = false;
}

void Crypt_Vigenere::set_key(const QString& data)
{
    if(data.isEmpty())
    {
        keyword = "ключ";
    }
    else
    {
        keyword = data.toLower();
    }
}

void Crypt_Vigenere::set_remove_spaces(bool remove)
{
    removeSpaces = remove;
}

bool Crypt_Vigenere::get_remove_spaces() const
{
    return removeSpaces;
}

QString Crypt_Vigenere::check_keyword() const
{
    return keyword;
}

QString Crypt_Vigenere::prepareKeyword(const QString& key, AlphabetType alphaType) const
{
    QString prepared;
    QString alphabet = (alphaType == AlphabetType::RUSSIAN) ?
                           russianAlphabet + "0123456789" :
                           englishAlphabet + "0123456789";
    alphabet = alphabet.toLower();

    for(const QChar& ch : key)
    {
        QChar lower = ch.toLower();
        if(alphabet.contains(lower))
        {
            prepared += lower;
        }
    }

    if(prepared.isEmpty())
    {
        prepared = (alphaType == AlphabetType::RUSSIAN) ? "ключ" : "key";
    }

    return prepared;
}

QChar Crypt_Vigenere::encryptChar(QChar ch, QChar key_char, const QString& alphabet) const
{
    if(!alphabet.contains(ch))
        return ch;

    int textIndex = alphabet.indexOf(ch);
    int keyIndex = alphabet.indexOf(key_char);

    if(textIndex == -1 || keyIndex == -1)
        return ch;

    int encryptedIndex = (textIndex + keyIndex) % alphabet.length();
    return alphabet[encryptedIndex];
}

QChar Crypt_Vigenere::decryptChar(QChar ch, QChar key_char, const QString& alphabet) const
{
    if(!alphabet.contains(ch))
        return ch;

    int textIndex = alphabet.indexOf(ch);
    int keyIndex = alphabet.indexOf(key_char);

    if(textIndex == -1 || keyIndex == -1)
        return ch;

    int decryptedIndex = (textIndex - keyIndex + alphabet.length()) % alphabet.length();
    return alphabet[decryptedIndex];
}

QByteArray Crypt_Vigenere::crypt(const QString& data)
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

    QString prepared_key = prepareKeyword(keyword, alphaType);

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
            QChar key_char = prepared_key[keyIndex % prepared_key.length()];
            result += encryptChar(ch, key_char, alphabet);
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

QByteArray Crypt_Vigenere::decrypt(const QByteArray& encryptedData)
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

    QString prepared_key = prepareKeyword(keyword, alphaType);

    QString result;
    int keyIndex = 0;

    for(const QChar& ch : encrypted)
    {
        if(alphabet.contains(ch))
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
