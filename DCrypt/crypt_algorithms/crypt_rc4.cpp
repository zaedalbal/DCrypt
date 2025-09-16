#include "crypt_rc4.h"
#include <algorithm>

Crypt_RC4::Crypt_RC4() : Crypt_Abs()
{
    key = QByteArray("defaultkey", 10);
}

void Crypt_RC4::set_key(const QString& data)
{
    key = data.toUtf8();
    if(key.isEmpty())
    {
        key = QByteArray("defaultkey", 10);
    }
}

QByteArray Crypt_RC4::check_key()
{
    return key;
}

QByteArray Crypt_RC4::crypt(const QString& data)
{
    QByteArray input = data.toUtf8();
    if(input.isEmpty())
        return QByteArray("[ОШИБКА: ПУСТЫЕ ВХОДНЫЕ ДАННЫЕ]");

    if(key.isEmpty())
        return QByteArray("[ОШИБКА: НЕ УСТАНОВЛЕН КЛЮЧ]");

    // инициаллизация S блока
    unsigned char S[256];
    for(int i = 0; i < 256; ++i)
        S[i] = i;

    // перимешивание S блока
    int j = 0;
    for(int i = 0; i < 256; ++i)
    {
        j = (j + S[i] + (unsigned char)key[i % key.size()]) % 256;
        std::swap(S[i], S[j]);
    }

    // генерация ключевого потока и шифрование
    QByteArray result;
    result.reserve(input.size());
    int i = 0;
    j = 0;

    for(int k = 0; k < input.size(); ++k)
    {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);

        unsigned char keystream_byte = S[(S[i] + S[j]) % 256];
        result.append((unsigned char)input[k] ^ keystream_byte);
    }

    return result;
}

QByteArray Crypt_RC4::decrypt(const QByteArray& encryptedData)
{
    if(encryptedData.startsWith("[ОШИБКА:"))
        return encryptedData;

    if(encryptedData.isEmpty())
        return QByteArray("[ОШИБКА: ПУСТЫЕ ЗАШИФРОВАННЫЕ ДАННЫЕ]");

    if(key.isEmpty())
        return QByteArray("[ОШИБКА: НЕ УСТАНОВЛЕН КЛЮЧ ДЛЯ РАСШИФРОВКИ]");

    // RC4 симметричен, та же операция для расшифровки
    unsigned char S[256];
    for(int i = 0; i < 256; ++i)
        S[i] = i;

    int j = 0;
    for(int i = 0; i < 256; ++i)
    {
        j = (j + S[i] + (unsigned char)key[i % key.size()]) % 256;
        std::swap(S[i], S[j]);
    }

    QByteArray result;
    result.reserve(encryptedData.size());
    int i = 0;
    j = 0;

    for(int k = 0; k < encryptedData.size(); ++k)
    {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);

        unsigned char keystream_byte = S[(S[i] + S[j]) % 256];
        result.append((unsigned char)encryptedData[k] ^ keystream_byte);
    }

    return result;
}
