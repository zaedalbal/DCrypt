#include "crypt_des.h"

#include <QDebug>
#include <windows.h>
#include <bcrypt.h>
#include <vector>

Crypt_Des::Crypt_Des() : Crypt_Abs()
{
    key = QByteArray(8, '\0');
}

void Crypt_Des::set_key(const QString& data)
{
    QByteArray buffer = data.toUtf8();
    if(buffer.size() < 8)
        buffer.append(QByteArray(8 - buffer.size(), '\0'));
    if(buffer.size() > 8)
        buffer = buffer.left(8);
    key = buffer;
}
QByteArray Crypt_Des::check_key()
{
    return key;
}

QByteArray Crypt_Des::crypt(const QString& data)
{
    QByteArray bytetextbuffer = check_data();
    PUCHAR plaintext = reinterpret_cast<PUCHAR>(bytetextbuffer.data());
    ULONG datalen = static_cast<ULONG>(bytetextbuffer.size());
    BCRYPT_ALG_HANDLE algh = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    NTSTATUS status;
    PUCHAR key_algh = reinterpret_cast<PUCHAR>(key.data());
    ULONG key_size = 8; // для DES нужен ключ из 8-ми байт

    status = BCryptOpenAlgorithmProvider(&algh, BCRYPT_DES_ALGORITHM, NULL, 0);
    if(status != 0)
    {
        qCritical() << "ERROR: CAN'T OPEN ALGORITHM\n";
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ ОТКРЫТЬ АЛГОРИТМ]");
    }

    status = BCryptGenerateSymmetricKey(algh, &hkey, NULL, 0, key_algh, key_size, 0);
    if(status != 0)
    {
        qCritical() << "ERROR: CAN'T GENERATE KEY\n";
        BCryptDestroyKey(hkey);
        BCryptCloseAlgorithmProvider(algh, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ СГЕНЕРИРОВАТЬ КЛЮЧ]");
    }
    DWORD cipherlen = 0;
    status = BCryptEncrypt(hkey,
                           plaintext,
                           datalen,
                           NULL,
                           NULL,
                           0,
                           NULL,
                           0,
                           &cipherlen,
                           BCRYPT_BLOCK_PADDING); // получение вхожных данных
    if(status != 0)
    {
        qCritical() << "ERROR: CRYPT ERROR\n";
        BCryptDestroyKey(hkey);
        BCryptCloseAlgorithmProvider(algh, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ ПОЛУЧИТЬ ВХОДНЫЕ ДАННЫЕ]");
    }
    std::vector<BYTE> cryptedtext(cipherlen);
    status = BCryptEncrypt(hkey,
                           plaintext,
                           datalen,
                           NULL,
                           NULL,
                           0,
                           cryptedtext.data(),
                           cipherlen,
                           &cipherlen,
                           BCRYPT_BLOCK_PADDING);
    if(status != 0)
    {
        qCritical() << "ERROR: CRYPT ERROR\n";
        BCryptDestroyKey(hkey);
        BCryptCloseAlgorithmProvider(algh, 0);
        return QByteArray("[ОШИБКА: ШИФРОВАНИЕ НЕ УДАЛОСЬ]");
    }
    BCryptDestroyKey(hkey);
    BCryptCloseAlgorithmProvider(algh, 0);
    return QByteArray(reinterpret_cast<const char*>(cryptedtext.data()), static_cast<int>(cryptedtext.size()));
}

QByteArray Crypt_Des::decrypt(const QByteArray& encryptedData)
{
    QByteArray encryptedDataCopy = encryptedData;
    PUCHAR ciphertext = reinterpret_cast<PUCHAR>(encryptedDataCopy.data());
    ULONG cipherlen = static_cast<ULONG>(encryptedData.size());
    BCRYPT_ALG_HANDLE algh = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    NTSTATUS status;
    PUCHAR key_algh = reinterpret_cast<PUCHAR>(key.data());
    ULONG key_size = 8; // для DES нужен ключ из 8-ми байт

    status = BCryptOpenAlgorithmProvider(&algh, BCRYPT_DES_ALGORITHM, NULL, 0);
    if(status != 0)
    {
        qCritical() << "ERROR: CAN'T OPEN ALGORITHM\n";
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ ОТКРЫТЬ АЛГОРИТМ]");
    }

    status = BCryptGenerateSymmetricKey(algh, &hkey, NULL, 0, key_algh, key_size, 0);
    if(status != 0)
    {
        qCritical() << "ERROR: CAN'T GENERATE KEY\n";
        BCryptDestroyKey(hkey);
        BCryptCloseAlgorithmProvider(algh, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ СГЕНЕРИРОВАТЬ КЛЮЧ]");
    }
    DWORD decryptedLen = 0;
    status = BCryptDecrypt(hkey,
                           ciphertext,
                           cipherlen,
                           NULL,
                           NULL,
                           0,
                           NULL,
                           0,
                           &decryptedLen,
                           BCRYPT_BLOCK_PADDING); // получение входных данных
    if(status != 0)
    {
        qCritical() << "ERROR: CAN'T DECRYPT DATA\n";
        BCryptDestroyKey(hkey);
        BCryptCloseAlgorithmProvider(algh, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ ПОЛУЧИТЬ ВХОДНЫЕ ДАННЫЕ]");
    }
    std::vector<BYTE> decryptedText(decryptedLen);
    status = BCryptDecrypt(hkey,
                           ciphertext,
                           cipherlen,
                           NULL,
                           NULL,
                           0,
                           decryptedText.data(),
                           decryptedLen,
                           &decryptedLen,
                           BCRYPT_BLOCK_PADDING);
    if(status != 0)
    {
        qCritical() << "ERROR: CAN'T DECRYPT DATA\n";
        BCryptDestroyKey(hkey);
        BCryptCloseAlgorithmProvider(algh, 0);
        return QByteArray("[ОШИБКА: РАСШИФРОВАНИЕ НЕ УДАЛОСЬ]");
    }
    BCryptDestroyKey(hkey);
    BCryptCloseAlgorithmProvider(algh, 0);
    return QByteArray(reinterpret_cast<const char*>(decryptedText.data()), decryptedLen);
}
