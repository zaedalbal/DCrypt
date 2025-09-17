#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <memory>

class QTextEdit;
class QLineEdit;
class QComboBox;
class QListWidget;
class QPushButton;
class QTabWidget;
class QHBoxLayout;
class QVBoxLayout;
class QWidget;
class QLabel;
class QGroupBox;
class QCheckBox;
class Crypt_Abs;
class Crypt_Alphabet_Abs;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void Encrypt_clicked();
    void Decrypt_clicked();
    void Generate_RSA_Keys();
    void Cipher_changed();

private:
    // UI элементы
    QTextEdit *inputTextPlain;
    QTextEdit *inputTextBytes;
    QTextEdit *outputTextPlain;
    QTextEdit *outputTextBytes;
    QLineEdit *keyEdit;
    QComboBox *cipherSelect;
    QPushButton *encryptButton;
    QPushButton *decryptButton;
    QPushButton *generateRSAButton;
    QCheckBox *removeSpacesCheckBox;

    // Контейнеры для разделения интерфейса
    QTabWidget *inputTabs;
    QTabWidget *outputTabs;
    QWidget *inputPlainWidget;
    QWidget *inputBytesWidget;
    QWidget *outputPlainWidget;
    QWidget *outputBytesWidget;

    // RSA компоненты
    QGroupBox *rsaGroup;
    QTextEdit *publicKeyDisplay;
    QTextEdit *privateKeyDisplay;

private:
    // Обновление ввода/вывода
    void updateInputBytesFromPlain();
    void updateInputPlainFromBytes();
    void updateOutputDisplays(const QByteArray& data);

    // Настройка интерфейса и алгоритмов
    void setupUI();
    void setupAlgorithms();
    void updateBinaryDisplayVisibility();

    // Проверка типа алгоритма
    bool isBinaryAlgorithm(const QString& algorithmName) const;
    bool isAlphabetAlgorithm(const QString& algorithmName) const;

    // Вспомогательные методы для работы с HEX
    QString bytesToHex(const QByteArray& data) const;
    QByteArray hexToBytes(const QString& hex) const;

    // Создание объектов шифров
    std::unique_ptr<Crypt_Abs> createBinaryCrypter(const QString& algorithm);
    std::unique_ptr<Crypt_Alphabet_Abs> createAlphabetCrypter(const QString& algorithm);
};

#endif
