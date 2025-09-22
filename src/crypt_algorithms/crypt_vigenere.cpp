#include "crypt_vigenere.h"

Crypt_Vigenere::Crypt_Vigenere() : Crypt_Alphabet_Abs()
{
    keyword = "key"; // используем английский по умолчанию
    currentAlphabet = AlphabetType::NONE;
    removeSpaces = false;
}

void Crypt_Vigenere::set_key(const QString& data)
{
    if(data.isEmpty())
    {
        keyword = "key";
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
        prepared = (alphaType == AlphabetType::RUSSIAN) ? "абвг" : "key";
    }

    return prepared;
}

QChar Crypt_Vigenere::encryptChar(QChar ch, QChar key_char, const QString& alphabet) const
{
    int textIndex = alphabet.indexOf(ch);
    int keyIndex = alphabet.indexOf(key_char);

    if(textIndex == -1 || keyIndex == -1)
        return ch;

    int encryptedIndex = (textIndex + keyIndex) % alphabet.length();
    return alphabet[encryptedIndex];
}

QChar Crypt_Vigenere::decryptChar(QChar ch, QChar key_char, const QString& alphabet) const
{
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

    QString prepared_key = prepareKeyword(keyword, alphaType);

    QString result;
    for(int i = 0; i < filteredData.length(); ++i)
    {
        QChar key_char = prepared_key[i % prepared_key.length()];
        result += encryptChar(filteredData[i], key_char, alphabet);
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

    QString alphabet = (alphaType == AlphabetType::RUSSIAN) ?
                           russianAlphabet.toLower() + "0123456789" :
                           englishAlphabet.toLower() + "0123456789";

    QString prepared_key = prepareKeyword(keyword, alphaType);

    QString result;
    for(int i = 0; i < encrypted.length(); ++i)
    {
        QChar key_char = prepared_key[i % prepared_key.length()];
        result += decryptChar(encrypted[i], key_char, alphabet);
    }

    return result.toUtf8();
}
