#include "mainwindow.h"
#include "crypt_algorithms/crypt_des.h"
#include "crypt_algorithms/crypt_des_cbc.h"
#include "crypt_algorithms/crypt_aes.h"
#include "crypt_algorithms/crypt_rsa.h"
#include "crypt_algorithms/crypt_rc4.h"
#include "crypt_algorithms/crypt_caesar.h"
#include "crypt_algorithms/crypt_vigenere.h"
#include <QTextEdit>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTabWidget>
#include <QLabel>
#include <QSplitter>
#include <QGroupBox>
#include <QMessageBox>
#include <QApplication>
#include <memory>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setupUI();
    setupAlgorithms();

    connect(encryptButton, &QPushButton::clicked, this, &MainWindow::Encrypt_clicked);
    connect(decryptButton, &QPushButton::clicked, this, &MainWindow::Decrypt_clicked);
    connect(generateRSAButton, &QPushButton::clicked, this, &MainWindow::Generate_RSA_Keys);
    connect(cipherSelect, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::Cipher_changed);

    connect(inputTextPlain, &QTextEdit::textChanged, this, &MainWindow::updateInputBytesFromPlain);
    connect(inputTextBytes, &QTextEdit::textChanged, this, &MainWindow::updateInputPlainFromBytes);
}

void MainWindow::setupUI()
{
    QWidget* central = new QWidget(this);
    setCentralWidget(central);
    setWindowTitle("DCrypt");
    resize(1000, 700);

    QVBoxLayout* mainLayout = new QVBoxLayout(central);

    QHBoxLayout* controlsLayout = new QHBoxLayout();

    QLabel* algorithmLabel = new QLabel("Алгоритм:");
    cipherSelect = new QComboBox(this);
    keyEdit = new QLineEdit(this);
    keyEdit->setPlaceholderText("Ключ шифрования");

    encryptButton = new QPushButton("Зашифровать", this);
    decryptButton = new QPushButton("Расшифровать", this);
    generateRSAButton = new QPushButton("Генерировать RSA ключи", this);

    controlsLayout->addWidget(algorithmLabel);
    controlsLayout->addWidget(cipherSelect);
    controlsLayout->addWidget(keyEdit);
    controlsLayout->addWidget(encryptButton);
    controlsLayout->addWidget(decryptButton);
    controlsLayout->addWidget(generateRSAButton);
    controlsLayout->addStretch();

    mainLayout->addLayout(controlsLayout);

    QSplitter* mainSplitter = new QSplitter(Qt::Vertical, this);

    QGroupBox* inputGroup = new QGroupBox("Входные данные", this);
    QVBoxLayout* inputLayout = new QVBoxLayout(inputGroup);

    inputTabs = new QTabWidget(this);

    inputPlainWidget = new QWidget();
    QVBoxLayout* plainInputLayout = new QVBoxLayout(inputPlainWidget);
    inputTextPlain = new QTextEdit(this);
    inputTextPlain->setPlaceholderText("Введите текст для шифрования...");
    plainInputLayout->addWidget(inputTextPlain);

    inputBytesWidget = new QWidget();
    QVBoxLayout* bytesInputLayout = new QVBoxLayout(inputBytesWidget);
    inputTextBytes = new QTextEdit(this);
    inputTextBytes->setPlaceholderText("Байтовое представление (HEX)...");
    inputTextBytes->setFont(QFont("Consolas", 10));
    bytesInputLayout->addWidget(inputTextBytes);

    inputTabs->addTab(inputPlainWidget, "Текст");
    inputTabs->addTab(inputBytesWidget, "Байты (HEX)");
    inputLayout->addWidget(inputTabs);

    QGroupBox* outputGroup = new QGroupBox("Результат", this);
    QVBoxLayout* outputLayout = new QVBoxLayout(outputGroup);

    outputTabs = new QTabWidget(this);

    outputPlainWidget = new QWidget();
    QVBoxLayout* plainOutputLayout = new QVBoxLayout(outputPlainWidget);
    outputTextPlain = new QTextEdit(this);
    outputTextPlain->setReadOnly(true);
    outputTextPlain->setPlaceholderText("Здесь появится результат...");
    plainOutputLayout->addWidget(outputTextPlain);

    outputBytesWidget = new QWidget();
    QVBoxLayout* bytesOutputLayout = new QVBoxLayout(outputBytesWidget);
    outputTextBytes = new QTextEdit(this);
    outputTextBytes->setReadOnly(true);
    outputTextBytes->setPlaceholderText("Байтовое представление результата...");
    outputTextBytes->setFont(QFont("Consolas", 10));
    bytesOutputLayout->addWidget(outputTextBytes);

    outputTabs->addTab(outputPlainWidget, "Текст");
    outputTabs->addTab(outputBytesWidget, "Байты (HEX)");
    outputLayout->addWidget(outputTabs);

    mainSplitter->addWidget(inputGroup);
    mainSplitter->addWidget(outputGroup);
    mainSplitter->setSizes({300, 300});

    mainLayout->addWidget(mainSplitter);

    rsaGroup = new QGroupBox("RSA Ключи", this);
    QHBoxLayout* rsaLayout = new QHBoxLayout(rsaGroup);

    QVBoxLayout* publicKeyLayout = new QVBoxLayout();
    QLabel* publicLabel = new QLabel("Открытый ключ:");
    publicKeyDisplay = new QTextEdit(this);
    publicKeyDisplay->setMaximumHeight(100);
    publicKeyDisplay->setReadOnly(true);
    publicKeyDisplay->setFont(QFont("Consolas", 8));
    publicKeyLayout->addWidget(publicLabel);
    publicKeyLayout->addWidget(publicKeyDisplay);

    QVBoxLayout* privateKeyLayout = new QVBoxLayout();
    QLabel* privateLabel = new QLabel("Приватный ключ:");
    privateKeyDisplay = new QTextEdit(this);
    privateKeyDisplay->setMaximumHeight(100);
    privateKeyDisplay->setReadOnly(true);
    privateKeyDisplay->setFont(QFont("Consolas", 8));
    privateKeyLayout->addWidget(privateLabel);
    privateKeyLayout->addWidget(privateKeyDisplay);

    rsaLayout->addLayout(publicKeyLayout);
    rsaLayout->addLayout(privateKeyLayout);

    rsaGroup->setVisible(false);
    mainLayout->addWidget(rsaGroup);
}

void MainWindow::setupAlgorithms()
{
    cipherSelect->clear();

    // Бинарные шифры
    cipherSelect->addItem("DES (ECB)");
    cipherSelect->addItem("DES (CBC)");
    cipherSelect->addItem("AES");
    cipherSelect->addItem("RSA");
    cipherSelect->addItem("RC4");

    // Алфавитные шифры
    cipherSelect->addItem("Caesar");
    cipherSelect->addItem("Vigenere");

    updateBinaryDisplayVisibility();
}

void MainWindow::updateBinaryDisplayVisibility()
{
    bool showBinary = isBinaryAlgorithm(cipherSelect->currentText());

    if (showBinary)
    {
        if (inputTabs->count() == 1)
        {
            inputTabs->addTab(inputBytesWidget, "Байты (HEX)");
        }
        if (outputTabs->count() == 1)
        {
            outputTabs->addTab(outputBytesWidget, "Байты (HEX)");
        }
    }
    else
    {
        int inputBytesIndex = inputTabs->indexOf(inputBytesWidget);
        if (inputBytesIndex != -1)
        {
            inputTabs->removeTab(inputBytesIndex);
        }

        int outputBytesIndex = outputTabs->indexOf(outputBytesWidget);
        if (outputBytesIndex != -1)
        {
            outputTabs->removeTab(outputBytesIndex);
        }
    }

    bool isRSA = cipherSelect->currentText() == "RSA";
    rsaGroup->setVisible(isRSA);
    generateRSAButton->setVisible(isRSA);
}

bool MainWindow::isBinaryAlgorithm(const QString& algorithmName) const
{
    QStringList binaryAlgorithms = {"DES (ECB)", "DES (CBC)", "AES", "RSA", "RC4"};
    return binaryAlgorithms.contains(algorithmName);
}

bool MainWindow::isAlphabetAlgorithm(const QString& algorithmName) const
{
    QStringList alphabetAlgorithms = {"Caesar", "Vigenere"};
    return alphabetAlgorithms.contains(algorithmName);
}

QString MainWindow::bytesToHex(const QByteArray& data) const
{
    return data.toHex(' ').toUpper();
}

QByteArray MainWindow::hexToBytes(const QString& hex) const
{
    QString cleanHex = hex;
    cleanHex.remove(' ').remove('\n').remove('\t');
    return QByteArray::fromHex(cleanHex.toUtf8());
}

void MainWindow::updateInputBytesFromPlain()
{
    if (inputTextBytes->hasFocus()) return;

    QString plainText = inputTextPlain->toPlainText();
    QByteArray utf8Data = plainText.toUtf8();
    inputTextBytes->blockSignals(true);
    inputTextBytes->setText(bytesToHex(utf8Data));
    inputTextBytes->blockSignals(false);
}

void MainWindow::updateInputPlainFromBytes()
{
    if (inputTextPlain->hasFocus()) return;

    QString hexText = inputTextBytes->toPlainText();
    QByteArray binaryData = hexToBytes(hexText);
    QString plainText = QString::fromUtf8(binaryData);

    inputTextPlain->blockSignals(true);
    inputTextPlain->setText(plainText);
    inputTextPlain->blockSignals(false);
}

void MainWindow::updateOutputDisplays(const QByteArray& data)
{
    QString textResult = QString::fromUtf8(data);
    outputTextPlain->setText(textResult);

    if (isBinaryAlgorithm(cipherSelect->currentText()))
    {
        outputTextBytes->setText(bytesToHex(data));
    }
}

std::unique_ptr<Crypt_Abs> MainWindow::createBinaryCrypter(const QString& algorithm)
{
    if (algorithm == "DES (ECB)")
    {
        return std::make_unique<Crypt_Des>();
    }
    else if (algorithm == "DES (CBC)")
    {
        return std::make_unique<Crypt_Des_CBC>();
    }
    else if (algorithm == "AES")
    {
        return std::make_unique<Crypt_AES>();
    }
    else if (algorithm == "RSA")
    {
        return std::make_unique<Crypt_RSA>();
    }
    else if (algorithm == "RC4")
    {
        return std::make_unique<Crypt_RC4>();
    }

    return nullptr;
}

std::unique_ptr<Crypt_Alphabet_Abs> MainWindow::createAlphabetCrypter(const QString& algorithm)
{
    if (algorithm == "Caesar")
    {
        return std::make_unique<Crypt_Caesar>();
    }
    else if (algorithm == "Vigenere")
    {
        return std::make_unique<Crypt_Vigenere>();
    }
    return nullptr;
}

void MainWindow::Cipher_changed()
{
    updateBinaryDisplayVisibility();

    outputTextPlain->clear();
    outputTextBytes->clear();

    QString algorithm = cipherSelect->currentText();

    // Настройка плейсхолдеров для ключей
    if (algorithm == "DES (ECB)" || algorithm == "DES (CBC)")
    {
        keyEdit->setPlaceholderText("Ключ DES (8 символов)");
        keyEdit->setEnabled(true);
    }
    else if (algorithm == "AES")
    {
        keyEdit->setPlaceholderText("Ключ AES (16/24/32 символа)");
        keyEdit->setEnabled(true);
    }
    else if (algorithm == "RSA")
    {
        keyEdit->setPlaceholderText("RSA использует генерацию ключей");
        keyEdit->setEnabled(false);
    }
    else if (algorithm == "RC4")
    {
        keyEdit->setPlaceholderText("Ключ RC4 (любая длина)");
        keyEdit->setEnabled(true);
    }
    else if (algorithm == "Caesar")
    {
        keyEdit->setPlaceholderText("Сдвиг (число)");
        keyEdit->setEnabled(true);
    }
    else if (algorithm == "Vigenere")
    {
        keyEdit->setPlaceholderText("Ключевое слово");
        keyEdit->setEnabled(true);
    }
    else
    {
        keyEdit->setPlaceholderText("Ключ шифрования");
        keyEdit->setEnabled(true);
    }
}

void MainWindow::Encrypt_clicked()
{
    QString plaintext = inputTextPlain->toPlainText();
    QString keyText = keyEdit->text();
    QString algorithm = cipherSelect->currentText();

    if (plaintext.isEmpty())
    {
        QMessageBox::warning(this, "Предупреждение", "Введите данные для шифрования!");
        return;
    }

    if (keyText.isEmpty() && algorithm != "RSA")
    {
        QMessageBox::warning(this, "Предупреждение", "Введите ключ шифрования!");
        return;
    }

    QByteArray encrypted;

    if (isBinaryAlgorithm(algorithm))
    {
        auto crypter = createBinaryCrypter(algorithm);
        if (!crypter)
        {
            outputTextPlain->setText("[ОШИБКА: НЕПОДДЕРЖИВАЕМЫЙ АЛГОРИТМ]");
            return;
        }

        if (algorithm == "RSA")
        {
            auto rsaCrypter = dynamic_cast<Crypt_RSA*>(crypter.get());
            if (publicKeyDisplay->toPlainText().isEmpty())
            {
                QMessageBox::warning(this, "Предупреждение", "Сначала сгенерируйте RSA ключи!");
                return;
            }

            QByteArray pubKey = QByteArray::fromBase64(publicKeyDisplay->toPlainText().toUtf8());
            rsaCrypter->set_public_key(pubKey);
        }
        else
        {
            crypter->set_key(keyText);
        }

        crypter->set_data(plaintext);
        encrypted = crypter->crypt(plaintext);
    }
    else if (isAlphabetAlgorithm(algorithm))
    {
        auto crypter = createAlphabetCrypter(algorithm);
        if (!crypter)
        {
            outputTextPlain->setText("[ОШИБКА: НЕПОДДЕРЖИВАЕМЫЙ АЛГОРИТМ]");
            return;
        }

        crypter->set_key(keyText);
        crypter->set_data(plaintext);
        encrypted = crypter->crypt(plaintext);
    }
    else
    {
        outputTextPlain->setText("[ОШИБКА: НЕИЗВЕСТНЫЙ ТИП АЛГОРИТМА]");
        return;
    }

    if (encrypted.startsWith("[ОШИБКА:"))
    {
        outputTextPlain->setText(QString::fromUtf8(encrypted));
        return;
    }

    if (isBinaryAlgorithm(algorithm))
    {
        QString encryptedBase64 = encrypted.toBase64();
        outputTextPlain->setText(encryptedBase64);
        outputTextBytes->setText(bytesToHex(encrypted));
    }
    else
    {
        updateOutputDisplays(encrypted);
    }
}

void MainWindow::Decrypt_clicked()
{
    QString keyStr = keyEdit->text();
    QString algorithm = cipherSelect->currentText();
    QString inputData = inputTextPlain->toPlainText();

    if (inputData.isEmpty())
    {
        QMessageBox::warning(this, "Предупреждение", "Введите зашифрованные данные!");
        return;
    }

    if (keyStr.isEmpty() && algorithm != "RSA")
    {
        QMessageBox::warning(this, "Предупреждение", "Введите ключ!");
        return;
    }

    QByteArray decryptedData;

    if (isBinaryAlgorithm(algorithm))
    {
        auto crypter = createBinaryCrypter(algorithm);
        if (!crypter)
        {
            outputTextPlain->setText("[ОШИБКА: НЕПОДДЕРЖИВАЕМЫЙ АЛГОРИТМ]");
            return;
        }

        QByteArray encryptedData = QByteArray::fromBase64(inputData.toLatin1());
        if (encryptedData.isEmpty())
        {
            outputTextPlain->setText("[ОШИБКА: НЕКОРРЕКТНЫЕ ДАННЫЕ ДЛЯ РАСШИФРОВКИ]");
            return;
        }

        if (algorithm == "RSA")
        {
            auto rsaCrypter = dynamic_cast<Crypt_RSA*>(crypter.get());
            if (privateKeyDisplay->toPlainText().isEmpty())
            {
                QMessageBox::warning(this, "Предупреждение", "Отсутствует приватный ключ RSA!");
                return;
            }

            QByteArray privKey = QByteArray::fromBase64(privateKeyDisplay->toPlainText().toUtf8());
            rsaCrypter->set_private_key(privKey);
        }
        else
        {
            crypter->set_key(keyStr);
        }

        decryptedData = crypter->decrypt(encryptedData);
    }
    else if (isAlphabetAlgorithm(algorithm))
    {
        auto crypter = createAlphabetCrypter(algorithm);
        if (!crypter)
        {
            outputTextPlain->setText("[ОШИБКА: НЕПОДДЕРЖИВАЕМЫЙ АЛГОРИТМ]");
            return;
        }

        crypter->set_key(keyStr);
        QByteArray inputBytes = inputData.toUtf8();
        decryptedData = crypter->decrypt(inputBytes);
    }
    else
    {
        outputTextPlain->setText("[ОШИБКА: НЕИЗВЕСТНЫЙ ТИП АЛГОРИТМА]");
        return;
    }

    if (decryptedData.startsWith("[ОШИБКА:"))
    {
        outputTextPlain->setText(QString::fromUtf8(decryptedData));
        return;
    }

    updateOutputDisplays(decryptedData);
}

void MainWindow::Generate_RSA_Keys()
{
    auto rsaCrypter = std::make_unique<Crypt_RSA>();
    rsaCrypter->generate_keys();

    QByteArray pubKey = rsaCrypter->get_public_key();
    QByteArray privKey = rsaCrypter->get_private_key();

    if (pubKey.isEmpty() || privKey.isEmpty())
    {
        QMessageBox::critical(this, "Ошибка", "Не удалось сгенерировать RSA ключи!");
        return;
    }

    publicKeyDisplay->setText(pubKey.toBase64());
    privateKeyDisplay->setText(privKey.toBase64());
}

MainWindow::~MainWindow() {}
