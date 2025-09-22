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

    QString prepared_key = prepareKey(oneTimePad, alphaType);

    // Проверяем длину ключа после фильтрации
    if(prepared_key.length() < filteredData.length())
    {
        return QByteArray("[ОШИБКА: ОДНОРАЗОВЫЙ БЛОКНОТ СЛИШКОМ КОРОТКИЙ]");
    }

    QString result;
    for(int i = 0; i < filteredData.length(); ++i)
    {
        QChar keyChar = prepared_key[i];
        result += encryptChar(filteredData[i], keyChar, alphabet);
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

    AlphabetType alphaType = detectAlphabet(encrypted);
    if(alphaType == AlphabetType::MIXED)
        return QByteArray("[ОШИБКА: СМЕШАННЫЕ АЛФАВИТЫ НЕ ПОДДЕРЖИВАЮТСЯ]");

    if(alphaType == AlphabetType::NONE)
        return QByteArray("[ОШИБКА: НЕ НАЙДЕНЫ БУКВЫ ДЛЯ РАСШИФРОВКИ]");

    QString alphabet = (alphaType == AlphabetType::RUSSIAN) ?
                           russianAlphabet.toLower() + "0123456789" :
                           englishAlphabet.toLower() + "0123456789";

    QString prepared_key = prepareKey(oneTimePad, alphaType);

    if(prepared_key.length() < encrypted.length())
    {
        return QByteArray("[ОШИБКА: ОДНОРАЗОВЫЙ БЛОКНОТ СЛИШКОМ КОРОТКИЙ ДЛЯ РАСШИФРОВКИ]");
    }

    QString result;
    for(int i = 0; i < encrypted.length(); ++i)
    {
        QChar keyChar = prepared_key[i];
        result += decryptChar(encrypted[i], keyChar, alphabet);
    }

    return result.toUtf8();
}
