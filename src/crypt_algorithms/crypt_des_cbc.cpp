#include "crypt_des_cbc.h"
#include <QDebug>
#include <QRandomGenerator>
#include <windows.h>
#include <bcrypt.h>
#include <vector>

Crypt_Des_CBC::Crypt_Des_CBC() : Crypt_Abs()
{
    key = QByteArray(8, '\0');
    iv = generate_random_iv();
}

void Crypt_Des_CBC::set_key(const QString& data)
{
    QByteArray buffer = data.toUtf8();
    if(buffer.size() < 8)
        buffer.append(QByteArray(8 - buffer.size(), '\0'));
    if(buffer.size() > 8)
        buffer = buffer.left(8);
    key = buffer;
}

QByteArray Crypt_Des_CBC::check_key()
{
    return key;
}

void Crypt_Des_CBC::set_iv(const QByteArray& custom_iv)
{
    if(custom_iv.size() != 8)
    {
        qWarning() << "IV должен быть длиной 8 байт для DES. Используется случайный IV.";
        iv = generate_random_iv();
    }
    else
    {
        iv = custom_iv;
    }
}

QByteArray Crypt_Des_CBC::check_iv() const
{
    return iv;
}

QByteArray Crypt_Des_CBC::generate_random_iv()
{
    QByteArray random_iv(8, '\0');
    auto* generator = QRandomGenerator::global();

    for(int i = 0; i < 8; ++i)
    {
        random_iv[i] = static_cast<char>(generator->bounded(256));
    }

    return random_iv;
}

QByteArray Crypt_Des_CBC::extract_iv_from_data(const QByteArray& data)
{
    if(data.size() < 8)
    {
        qCritical() << "Данные слишком короткие для извлечения IV";
        return QByteArray();
    }
    return data.left(8);
}

QByteArray Crypt_Des_CBC::remove_iv_from_data(const QByteArray& data)
{
    if(data.size() < 8)
    {
        qCritical() << "Данные слишком короткие";
        return QByteArray();
    }
    return data.mid(8);
}

QByteArray Crypt_Des_CBC::crypt(const QString& data)
{
    QByteArray bytetextbuffer = check_data();
    PUCHAR plaintext = reinterpret_cast<PUCHAR>(bytetextbuffer.data());
    ULONG datalen = static_cast<ULONG>(bytetextbuffer.size());

    BCRYPT_ALG_HANDLE algh = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    NTSTATUS status;

    PUCHAR key_algh = reinterpret_cast<PUCHAR>(key.data());
    ULONG key_size = 8;

    iv = generate_random_iv();
    PUCHAR iv_ptr = reinterpret_cast<PUCHAR>(iv.data());

    status = BCryptOpenAlgorithmProvider(&algh, BCRYPT_DES_ALGORITHM, NULL, 0);
    if(status != 0)
    {
        qCritical() << "ERROR: CAN'T OPEN ALGORITHM";
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ ОТКРЫТЬ АЛГОРИТМ]");
    }

    status = BCryptSetProperty(algh,
                               BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                               sizeof(BCRYPT_CHAIN_MODE_CBC),
                               0);
    if(status != 0)
    {
        qCritical() << "ERROR: CAN'T SET CBC MODE";
        BCryptCloseAlgorithmProvider(algh, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ УСТАНОВИТЬ CBC РЕЖИМ]");
    }

    status = BCryptGenerateSymmetricKey(algh, &hkey, NULL, 0, key_algh, key_size, 0);
    if(status != 0)
    {
        qCritical() << "ERROR: CAN'T GENERATE KEY";
        BCryptCloseAlgorithmProvider(algh, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ СГЕНЕРИРОВАТЬ КЛЮЧ]");
    }

    DWORD cipherlen = 0;
    status = BCryptEncrypt(hkey,
                           plaintext,
                           datalen,
                           NULL,
                           iv_ptr,  // IV для CBC
                           8,       // Размер IV
                           NULL,
                           0,
                           &cipherlen,
                           BCRYPT_BLOCK_PADDING);
    if(status != 0)
    {
        qCritical() << "ERROR: CAN'T GET OUTPUT SIZE";
        BCryptDestroyKey(hkey);
        BCryptCloseAlgorithmProvider(algh, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ ПОЛУЧИТЬ ВХОДНЫЕ ДАННЫЕ]");
    }

    std::vector<BYTE> cryptedtext(cipherlen);
    QByteArray iv_copy = iv;
    PUCHAR iv_copy_ptr = reinterpret_cast<PUCHAR>(iv_copy.data());

    status = BCryptEncrypt(hkey,
                           plaintext,
                           datalen,
                           NULL,
                           iv_copy_ptr,
                           8,
                           cryptedtext.data(),
                           cipherlen,
                           &cipherlen,
                           BCRYPT_BLOCK_PADDING);
    if(status != 0)
    {
        qCritical() << "ERROR: ENCRYPTION FAILED";
        BCryptDestroyKey(hkey);
        BCryptCloseAlgorithmProvider(algh, 0);
        return QByteArray("[ОШИБКА: ОШИБКА ШИФРОВАНИЯ]");
    }

    BCryptDestroyKey(hkey);
    BCryptCloseAlgorithmProvider(algh, 0);

    QByteArray result = iv + QByteArray(reinterpret_cast<const char*>(cryptedtext.data()), static_cast<int>(cipherlen));
    return result;
}

QByteArray Crypt_Des_CBC::decrypt(const QByteArray& encryptedData)
{
    if(encryptedData.size() < 8)
    {
        qCritical() << "ERROR: Зашифрованные данные слишком короткие";
        return QByteArray("[ОШИБКА: ЗАШИФРОВАННЫЕ ДАННЫЕ СЛИШКОМ КОРОТКИЕ]");
    }

    QByteArray extracted_iv = extract_iv_from_data(encryptedData);
    QByteArray cipher_data = remove_iv_from_data(encryptedData);

    PUCHAR ciphertext = reinterpret_cast<PUCHAR>(cipher_data.data());
    ULONG cipherlen = static_cast<ULONG>(cipher_data.size());

    BCRYPT_ALG_HANDLE algh = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    NTSTATUS status;

    PUCHAR key_algh = reinterpret_cast<PUCHAR>(key.data());
    ULONG key_size = 8;
    PUCHAR iv_ptr = reinterpret_cast<PUCHAR>(extracted_iv.data());

    status = BCryptOpenAlgorithmProvider(&algh, BCRYPT_DES_ALGORITHM, NULL, 0);
    if(status != 0)
    {
        qCritical() << "ERROR: CAN'T OPEN ALGORITHM";
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ ОТКРЫТЬ АЛГОРИТМ]");
    }

    status = BCryptSetProperty(algh,
                               BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                               sizeof(BCRYPT_CHAIN_MODE_CBC),
                               0);
    if(status != 0)
    {
        qCritical() << "ERROR: CAN'T SET CBC MODE";
        BCryptCloseAlgorithmProvider(algh, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ УСТАНОВИТЬ CBC РЕЖИМ]");
    }

    status = BCryptGenerateSymmetricKey(algh, &hkey, NULL, 0, key_algh, key_size, 0);
    if(status != 0)
    {
        qCritical() << "ERROR: CAN'T GENERATE KEY";
        BCryptCloseAlgorithmProvider(algh, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ СГЕНЕРИРОВАТЬ КЛЮЧ]");
    }

    DWORD decryptedLen = 0;
    status = BCryptDecrypt(hkey,
                           ciphertext,
                           cipherlen,
                           NULL,
                           iv_ptr,
                           8,
                           NULL,
                           0,
                           &decryptedLen,
                           BCRYPT_BLOCK_PADDING);
    if(status != 0)
    {
        qCritical() << "ERROR: CAN'T GET DECRYPTED SIZE";
        BCryptDestroyKey(hkey);
        BCryptCloseAlgorithmProvider(algh, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ ПОЛУЧИТЬ ВХОДНЫЕ ДАННЫЕ]");
    }

    std::vector<BYTE> decryptedText(decryptedLen);
    QByteArray iv_copy = extracted_iv;
    PUCHAR iv_copy_ptr = reinterpret_cast<PUCHAR>(iv_copy.data());

    status = BCryptDecrypt(hkey,
                           ciphertext,
                           cipherlen,
                           NULL,
                           iv_copy_ptr,
                           8,
                           decryptedText.data(),
                           decryptedLen,
                           &decryptedLen,
                           BCRYPT_BLOCK_PADDING);
    if(status != 0)
    {
        qCritical() << "ERROR: DECRYPTION FAILED";
        BCryptDestroyKey(hkey);
        BCryptCloseAlgorithmProvider(algh, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ РАСШИФРОВАТЬ ДАННЫЕ]");
    }

    BCryptDestroyKey(hkey);
    BCryptCloseAlgorithmProvider(algh, 0);

    return QByteArray(reinterpret_cast<const char*>(decryptedText.data()), decryptedLen);
}
