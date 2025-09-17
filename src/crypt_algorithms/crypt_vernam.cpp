#include "crypt_vernam.h"

Crypt_Vernam::Crypt_Vernam() : Crypt_Alphabet_Abs()
{
    oneTimePad = "абвгдежзийклмнопрстуфхцчшщъыьэюя";
    currentAlphabet = AlphabetType::NONE;
    removeSpaces = false;
}

void Crypt_Vernam::set_key(const QString& data)
{
    if(data.isEmpty())
    {
        oneTimePad = "абвгдежзийклмнопрстуфхцчшщъыьэюя";
    }
    else
    {
        oneTimePad = data.toLower();
    }
}

void Crypt_Vernam::set_remove_spaces(bool remove)
{
    removeSpaces = remove;
}

bool Crypt_Vernam::get_remove_spaces() const
{
    return removeSpaces;
}

QString Crypt_Vernam::check_one_time_pad() const
{
    return oneTimePad;
}

QString Crypt_Vernam::prepareKey(const QString& key, AlphabetType alphaType) const
{
    QString prepared;
    QString alphabet = (alphaType == AlphabetType::RUSSIAN) ?
                           russianAlphabet + "0123456789" :
                           englishAlphabet + "0123456789";
    alphabet = alphabet.toLower();

    for(const QChar& ch : key)
    {
        if(alphabet.contains(ch.toLower()))
        {
            prepared += ch.toLower();
        }
    }

    if(prepared.isEmpty())
    {
        prepared = (alphaType == AlphabetType::RUSSIAN) ?
                       "абвгдежзийклмнопрстуфхцчшщъыьэюя" :
                       "abcdefghijklmnopqrstuvwxyz";
    }

    return prepared;
}

QChar Crypt_Vernam::encryptChar(QChar ch, QChar keyChar, const QString& alphabet) const
{
    if(!alphabet.contains(ch))
        return ch;

    int textIndex = alphabet.indexOf(ch);
    int keyIndex = alphabet.indexOf(keyChar);

    if(textIndex == -1 || keyIndex == -1)
        return ch;

    int encryptedIndex = (textIndex + keyIndex) % alphabet.length();
    return alphabet[encryptedIndex];
}

QChar Crypt_Vernam::decryptChar(QChar ch, QChar keyChar, const QString& alphabet) const
{
    if(!alphabet.contains(ch))
        return ch;

    int textIndex = alphabet.indexOf(ch);
    int keyIndex = alphabet.indexOf(keyChar);

    if(textIndex == -1 || keyIndex == -1)
        return ch;

    int decryptedIndex = (textIndex - keyIndex + alphabet.length()) % alphabet.length();
    return alphabet[decryptedIndex];
}

QByteArray Crypt_Vernam::crypt(const QString& data)
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

    QString prepared_key = prepareKey(oneTimePad, alphaType);

    // кол-во символов для шифрования
    int symbolCount = 0;
    for(const QChar& ch : processedData)
    {
        if(alphabet.contains(ch))
        {
            symbolCount++;
        }
    }

    if(prepared_key.length() < symbolCount)
    {
        return QByteArray("[ОШИБКА: ОДНОРАЗОВЫЙ БЛОКНОТ СЛИШКОМ КОРОТКИЙ]");
    }

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
            QChar keyChar = prepared_key[keyIndex];
            result += encryptChar(ch, keyChar, alphabet);
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

QByteArray Crypt_Vernam::decrypt(const QByteArray& encryptedData)
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

    QString prepared_key = prepareKey(oneTimePad, alphaType);

    QString result;
    int keyIndex = 0;

    for(const QChar& ch : encrypted)
    {
        if(alphabet.contains(ch))
        {
            if(keyIndex >= prepared_key.length())
            {
                return QByteArray("[ОШИБКА: ОДНОРАЗОВЫЙ БЛОКНОТ СЛИШКОМ КОРОТКИЙ ДЛЯ РАСШИФРОВКИ]");
            }
            QChar keyChar = prepared_key[keyIndex];
            result += decryptChar(ch, keyChar, alphabet);
            keyIndex++;
        }
        else
        {
            result += ch;
        }
    }

    return result.toUtf8();
}
