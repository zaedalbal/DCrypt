#include "crypt_rsa.h"
#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <QDebug>

Crypt_RSA::Crypt_RSA() : Crypt_Abs()
{
    keys_generated = false;
}

void Crypt_RSA::set_key(const QString& data)
{
    private_key = data.toUtf8();
    if (!private_key.isEmpty()) {
        keys_generated = true;
    }
}

void Crypt_RSA::generate_keys()
{
    BCRYPT_ALG_HANDLE alg_handle = NULL;
    BCRYPT_KEY_HANDLE key_handle = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&alg_handle, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if(status != 0)
    {
        qDebug() << "Ошибка BCryptOpenAlgorithmProvider:" << QString::number(status, 16);
        keys_generated = false;
        return;
    }

    status = BCryptGenerateKeyPair(alg_handle, &key_handle, 2048, 0);
    if(status != 0)
    {
        qDebug() << "Ошибка BCryptGenerateKeyPair:" << QString::number(status, 16);
        BCryptCloseAlgorithmProvider(alg_handle, 0);
        keys_generated = false;
        return;
    }

    status = BCryptFinalizeKeyPair(key_handle, 0);
    if(status != 0)
    {
        qDebug() << "Ошибка BCryptFinalizeKeyPair:" << QString::number(status, 16);
        BCryptDestroyKey(key_handle);
        BCryptCloseAlgorithmProvider(alg_handle, 0);
        keys_generated = false;
        return;
    }

    DWORD pub_key_size = 0;
    status = BCryptExportKey(key_handle, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &pub_key_size, 0);
    if(status != 0)
    {
        qDebug() << "Ошибка получения размера публичного ключа:" << QString::number(status, 16);
        BCryptDestroyKey(key_handle);
        BCryptCloseAlgorithmProvider(alg_handle, 0);
        keys_generated = false;
        return;
    }
    std::vector<BYTE> pub_key_data(pub_key_size);
    status = BCryptExportKey(key_handle, NULL, BCRYPT_RSAPUBLIC_BLOB,
                             pub_key_data.data(), pub_key_size, &pub_key_size, 0);
    if(status != 0)
    {
        qDebug() << "Ошибка экспорта публичного ключа:" << QString::number(status, 16);
        BCryptDestroyKey(key_handle);
        BCryptCloseAlgorithmProvider(alg_handle, 0);
        keys_generated = false;
        return;
    }

    DWORD priv_key_size = 0;
    status = BCryptExportKey(key_handle, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, 0, &priv_key_size, 0);
    if(status != 0)
    {
        qDebug() << "Ошибка получения размера приватного ключа:" << QString::number(status, 16);
        BCryptDestroyKey(key_handle);
        BCryptCloseAlgorithmProvider(alg_handle, 0);
        keys_generated = false;
        return;
    }
    std::vector<BYTE> priv_key_data(priv_key_size);
    status = BCryptExportKey(key_handle, NULL, BCRYPT_RSAPRIVATE_BLOB,
                             priv_key_data.data(), priv_key_size, &priv_key_size, 0);
    if(status == 0)
    {
        public_key = QByteArray(reinterpret_cast<const char*>(pub_key_data.data()), pub_key_size);
        private_key = QByteArray(reinterpret_cast<const char*>(priv_key_data.data()), priv_key_size);
        keys_generated = true;
        qDebug() << "Ключи успешно сгенерированы. Размер публичного:" << pub_key_size
                 << "Размер приватного:" << priv_key_size;
    }
    else
    {
        qDebug() << "Ошибка экспорта приватного ключа:" << QString::number(status, 16);
        keys_generated = false;
    }

    BCryptDestroyKey(key_handle);
    BCryptCloseAlgorithmProvider(alg_handle, 0);
}

QByteArray Crypt_RSA::get_public_key() const
{
    return public_key;
}

QByteArray Crypt_RSA::get_private_key() const
{
    return private_key;
}

void Crypt_RSA::set_public_key(const QByteArray& pubkey)
{
    public_key = pubkey;
    if(!pubkey.isEmpty())
    {
        keys_generated = true;
    }
}

void Crypt_RSA::set_private_key(const QByteArray& privkey)
{
    private_key = privkey;
    if(!privkey.isEmpty())
    {
        keys_generated = true;
    }
}

QByteArray Crypt_RSA::crypt(const QString& data)
{
    // проверка состояния ключей
    if(!keys_generated || public_key.isEmpty())
    {
        qDebug() << "Ключи не готовы. keys_generated:" << keys_generated
                 << "public_key.isEmpty():" << public_key.isEmpty();
        return QByteArray("[ОШИБКА: НЕ УСТАНОВЛЕН ОТКРЫТЫЙ КЛЮЧ]");
    }
    QByteArray input = data.toUtf8();
    if(input.isEmpty())
    {
        return QByteArray("[ОШИБКА: ПУСТЫЕ ВХОДНЫЕ ДАННЫЕ]");
    }

    const int MAX_RSA_OAEP_SIZE = 190;  // максимум 190 байт
    if(input.size() > MAX_RSA_OAEP_SIZE)
    {
        qDebug() << "Размер данных:" << input.size() << "байт, максимум:" << MAX_RSA_OAEP_SIZE;
        return QByteArray("[ОШИБКА: ДАННЫЕ СЛИШКОМ БОЛЬШИЕ ДЛЯ RSA (MAX 190 БАЙТ)]");
    }
    BCRYPT_ALG_HANDLE alg_handle = NULL;
    BCRYPT_KEY_HANDLE key_handle = NULL;
    NTSTATUS status;
    status = BCryptOpenAlgorithmProvider(&alg_handle, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if(status != 0)
    {
        qDebug() << "Ошибка открытия алгоритма для шифрования:" << QString::number(status, 16);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ ОТКРЫТЬ АЛГОРИТМ]");
    }

    status = BCryptImportKeyPair(alg_handle, NULL, BCRYPT_RSAPUBLIC_BLOB, &key_handle,
                                 reinterpret_cast<PUCHAR>(public_key.data()),
                                 static_cast<ULONG>(public_key.size()), 0);
    if(status != 0)
    {
        qDebug() << "Ошибка импорта публичного ключа:" << QString::number(status, 16)
            << "Размер ключа:" << public_key.size();
        BCryptCloseAlgorithmProvider(alg_handle, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ ИМПОРТИРОВАТЬ ОТКРЫТЫЙ КЛЮЧ]");
    }
    // для того чтобы одинаковые данные шифровались по разному
    BCRYPT_OAEP_PADDING_INFO paddingInfo;
    paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    paddingInfo.pbLabel = NULL;
    paddingInfo.cbLabel = 0;

    DWORD cipher_size = 0;
    status = BCryptEncrypt(key_handle,
                           reinterpret_cast<PUCHAR>(input.data()),
                           static_cast<ULONG>(input.size()),
                           &paddingInfo, NULL, 0, NULL, 0, &cipher_size, BCRYPT_PAD_OAEP);
    if(status != 0)
    {
        qDebug() << "Ошибка определения размера шифра:" << QString::number(status, 16);
        BCryptDestroyKey(key_handle);
        BCryptCloseAlgorithmProvider(alg_handle, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ ОПРЕДЕЛИТЬ РАЗМЕР ШИФРА]");
    }

    std::vector<BYTE> cipher_data(cipher_size);
    status = BCryptEncrypt(key_handle,
                           reinterpret_cast<PUCHAR>(input.data()),
                           static_cast<ULONG>(input.size()),
                           &paddingInfo, NULL, 0,
                           cipher_data.data(), cipher_size, &cipher_size, BCRYPT_PAD_OAEP);
    if(status != 0)
    {
        qDebug() << "Ошибка шифрования:" << QString::number(status, 16);
        BCryptDestroyKey(key_handle);
        BCryptCloseAlgorithmProvider(alg_handle, 0);
        return QByteArray("[ОШИБКА: ШИФРОВАНИЕ НЕ УДАЛОСЬ]");
    }

    BCryptDestroyKey(key_handle);
    BCryptCloseAlgorithmProvider(alg_handle, 0);
    qDebug() << "Шифрование успешно. Размер шифра:" << cipher_size << "байт";
    return QByteArray(reinterpret_cast<const char*>(cipher_data.data()), cipher_size);
}

QByteArray Crypt_RSA::decrypt(const QByteArray& encryptedData)
{
    if(!keys_generated || private_key.isEmpty()) // проверка готовности ключей
    {
        qDebug() << "Приватный ключ не готов. keys_generated:" << keys_generated
                 << "private_key.isEmpty():" << private_key.isEmpty();
        return QByteArray("[ОШИБКА: НЕ УСТАНОВЛЕН ПРИВАТНЫЙ КЛЮЧ]");
    }
    if(encryptedData.isEmpty())
    {
        return QByteArray("[ОШИБКА: ПУСТЫЕ ЗАШИФРОВАННЫЕ ДАННЫЕ]");
    }
    BCRYPT_ALG_HANDLE alg_handle = NULL;
    BCRYPT_KEY_HANDLE key_handle = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&alg_handle, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if(status != 0)
    {
        qDebug() << "Ошибка открытия алгоритма для дешифрования:" << QString::number(status, 16);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ ОТКРЫТЬ АЛГОРИТМ]");
    }

    status = BCryptImportKeyPair(alg_handle, NULL, BCRYPT_RSAPRIVATE_BLOB, &key_handle,
                                 reinterpret_cast<PUCHAR>(private_key.data()),
                                 static_cast<ULONG>(private_key.size()), 0);
    if(status != 0)
    {
        qDebug() << "Ошибка импорта приватного ключа:" << QString::number(status, 16)
            << "Размер ключа:" << private_key.size();
        BCryptCloseAlgorithmProvider(alg_handle, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ ИМПОРТИРОВАТЬ ПРИВАТНЫЙ КЛЮЧ]");
    }
    // для того чтобы одинаковые данные шифровались по разному
    BCRYPT_OAEP_PADDING_INFO paddingInfo;
    paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    paddingInfo.pbLabel = NULL;
    paddingInfo.cbLabel = 0;
    // копия данных для безопасности (мб это бесполезно, но нейронка сказала что так надо =) )
    QByteArray encrypted_copy = encryptedData;

    DWORD plain_size = 0;
    status = BCryptDecrypt(key_handle,
                           reinterpret_cast<PUCHAR>(encrypted_copy.data()),
                           static_cast<ULONG>(encrypted_copy.size()),
                           &paddingInfo, NULL, 0, NULL, 0, &plain_size, BCRYPT_PAD_OAEP);
    if(status != 0)
    {
        qDebug() << "Ошибка определения размера расшифрованных данных:" << QString::number(status, 16);
        BCryptDestroyKey(key_handle);
        BCryptCloseAlgorithmProvider(alg_handle, 0);
        return QByteArray("[ОШИБКА: НЕ УДАЛОСЬ ПОЛУЧИТЬ РАЗМЕР ДАННЫХ]");
    }

    std::vector<BYTE> plain_data(plain_size);
    status = BCryptDecrypt(key_handle,
                           reinterpret_cast<PUCHAR>(encrypted_copy.data()),
                           static_cast<ULONG>(encrypted_copy.size()),
                           &paddingInfo, NULL, 0,
                           plain_data.data(), plain_size, &plain_size, BCRYPT_PAD_OAEP);
    if(status != 0)
    {
        qDebug() << "Ошибка расшифровки:" << QString::number(status, 16);
        BCryptDestroyKey(key_handle);
        BCryptCloseAlgorithmProvider(alg_handle, 0);
        return QByteArray("[ОШИБКА: РАСШИФРОВКА НЕ УДАЛАСЬ]");
    }

    BCryptDestroyKey(key_handle);
    BCryptCloseAlgorithmProvider(alg_handle, 0);
    qDebug() << "Расшифровка успешна. Размер данных:" << plain_size << "байт";
    return QByteArray(reinterpret_cast<const char*>(plain_data.data()), plain_size);
}
