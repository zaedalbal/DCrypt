#include "crypt_aes.h"
#include <QRandomGenerator>
#include <windows.h>
#include <bcrypt.h>
#include <vector>

Crypt_AES::Crypt_AES() : Crypt_Abs()
{
    key = QByteArray(32, '\0'); // AES-256 ключ по умолчанию
    iv = generate_random_iv();
}

void Crypt_AES::set_key(const QString& data)
{
    QByteArray buffer = data.toUtf8();

    if(buffer.size() <= 16) // подержка AES-128, AES-192, AES-256
    {
        buffer.resize(16, '\0'); // AES-128
    }
    else if(buffer.size() <= 24)
    {
        buffer.resize(24, '\0'); // AES-192
    }
    else
    {
        buffer.resize(32, '\0'); // AES-256
    }

    key = buffer;
}

QByteArray Crypt_AES::check_key()
{
    return key;
}

void Crypt_AES::set_iv(const QByteArray& custom_iv)
{
    if(custom_iv.size() != 16)
    {
        iv = generate_random_iv();
    }
    else
    {
        iv = custom_iv;
    }
}

QByteArray Crypt_AES::generate_random_iv()
{
    QByteArray random_iv(16, '\0');
    auto* generator = QRandomGenerator::global();

    for(int i = 0; i < 16; ++i)
    {
        random_iv[i] = static_cast<char>(generator->bounded(256));
    }

    return random_iv;
}

QByteArray Crypt_AES::crypt(const QString& data)
{
    QByteArray bytetextbuffer = check_data();
    PUCHAR plaintext = reinterpret_cast<PUCHAR>(bytetextbuffer.data());
    ULONG datalen = static_cast<ULONG>(bytetextbuffer.size());

    BCRYPT_ALG_HANDLE algh = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    NTSTATUS status;

    PUCHAR key_ptr = reinterpret_cast<PUCHAR>(key.data());
    ULONG key_size = key.size();

    iv = generate_random_iv();
    PUCHAR iv_ptr = reinterpret_cast<PUCHAR>(iv.data());

    status = BCryptOpenAlgorithmProvider(&algh, BCRYPT_AES_ALGORITHM, NULL, 0);
    if(status != 0)
    {
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ ОТКРЫТЬ АЛГОРИТМ AES]");
    }

    status = BCryptSetProperty(algh, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0); // режим CBC
    if(status != 0)
    {
        BCryptCloseAlgorithmProvider(algh, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ УСТАНОВИТЬ РЕЖИМ CBC]");
    }

    status = BCryptGenerateSymmetricKey(algh, &hkey, NULL, 0, key_ptr, key_size, 0);
    if(status != 0)
    {
        BCryptCloseAlgorithmProvider(algh, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ СОЗДАТЬ КЛЮЧ AES]");
    }

    DWORD cipherlen = 0;
    status = BCryptEncrypt(hkey, plaintext, datalen, NULL, iv_ptr, 16, NULL, 0, &cipherlen, BCRYPT_BLOCK_PADDING);
    if(status != 0)
    {
        BCryptDestroyKey(hkey);
        BCryptCloseAlgorithmProvider(algh, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ ОПРЕДЕЛИТЬ РАЗМЕР ВЫХОДНЫХ ДАННЫХ]");
    }

    std::vector<BYTE> cryptedtext(cipherlen);
    QByteArray iv_copy = iv;
    PUCHAR iv_copy_ptr = reinterpret_cast<PUCHAR>(iv_copy.data());

    status = BCryptEncrypt(hkey, plaintext, datalen, NULL, iv_copy_ptr, 16, cryptedtext.data(), cipherlen, &cipherlen, BCRYPT_BLOCK_PADDING);
    if(status != 0)
    {
        BCryptDestroyKey(hkey);
        BCryptCloseAlgorithmProvider(algh, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ ЗАШИФРОВАТЬ ДАННЫЕ]");
    }

    BCryptDestroyKey(hkey);
    BCryptCloseAlgorithmProvider(algh, 0);

    return iv + QByteArray(reinterpret_cast<const char*>(cryptedtext.data()), static_cast<int>(cipherlen)); // IV + зашифрованные данные
}

QByteArray Crypt_AES::decrypt(const QByteArray& encryptedData)
{
    if(encryptedData.size() < 16)
    {
        return QByteArray("[ОШИБКА: ЗАШИФРОВАННЫЕ ДАННЫЕ СЛИШКОМ КОРОТКИЕ]");
    }

    QByteArray extracted_iv = encryptedData.left(16); // получение IV из начала данных
    QByteArray cipher_data = encryptedData.mid(16);

    PUCHAR ciphertext = reinterpret_cast<PUCHAR>(cipher_data.data());
    ULONG cipherlen = static_cast<ULONG>(cipher_data.size());

    BCRYPT_ALG_HANDLE algh = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    NTSTATUS status;

    PUCHAR key_ptr = reinterpret_cast<PUCHAR>(key.data());
    ULONG key_size = key.size();
    PUCHAR iv_ptr = reinterpret_cast<PUCHAR>(extracted_iv.data());

    status = BCryptOpenAlgorithmProvider(&algh, BCRYPT_AES_ALGORITHM, NULL, 0);
    if(status != 0)
    {
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ ОТКРЫТЬ АЛГОРИТМ AES ДЛЯ РАСШИФРОВКИ]");
    }

    status = BCryptSetProperty(algh, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0); // Устанавливаем режим CBC
    if(status != 0)
    {
        BCryptCloseAlgorithmProvider(algh, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ УСТАНОВИТЬ РЕЖИМ CBC ДЛЯ РАСШИФРОВКИ]");
    }

    status = BCryptGenerateSymmetricKey(algh, &hkey, NULL, 0, key_ptr, key_size, 0);
    if(status != 0)
    {
        BCryptCloseAlgorithmProvider(algh, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ СОЗДАТЬ КЛЮЧ ДЛЯ РАСШИФРОВКИ]");
    }

    DWORD decryptedLen = 0;
    status = BCryptDecrypt(hkey, ciphertext, cipherlen, NULL, iv_ptr, 16, NULL, 0, &decryptedLen, BCRYPT_BLOCK_PADDING);
    if(status != 0)
    {
        BCryptDestroyKey(hkey);
        BCryptCloseAlgorithmProvider(algh, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ ОПРЕДЕЛИТЬ РАЗМЕР РАСШИФРОВАННЫХ ДАННЫХ]");
    }

    std::vector<BYTE> decryptedText(decryptedLen);
    QByteArray iv_copy = extracted_iv;
    PUCHAR iv_copy_ptr = reinterpret_cast<PUCHAR>(iv_copy.data());

    status = BCryptDecrypt(hkey, ciphertext, cipherlen, NULL, iv_copy_ptr, 16, decryptedText.data(), decryptedLen, &decryptedLen, BCRYPT_BLOCK_PADDING);
    if(status != 0)
    {
        BCryptDestroyKey(hkey);
        BCryptCloseAlgorithmProvider(algh, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ РАСШИФРОВАТЬ ДАННЫЕ]");
    }

    BCryptDestroyKey(hkey);
    BCryptCloseAlgorithmProvider(algh, 0);

    return QByteArray(reinterpret_cast<const char*>(decryptedText.data()), decryptedLen);
}
