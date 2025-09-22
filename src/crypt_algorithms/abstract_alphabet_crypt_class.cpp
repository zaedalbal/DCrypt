#include "abstract_alphabet_crypt_class.h"

AlphabetType Crypt_Alphabet_Abs::detectAlphabet(const QString& text) const
{
    bool hasRussian = false;
    bool hasEnglish = false;

    for(const QChar& ch : text)
    {
        if(isRussianChar(ch))
        {
            hasRussian = true;
        }
        else if(isEnglishChar(ch))
        {
            hasEnglish = true;
        }

        if(hasRussian && hasEnglish)
        {
            return AlphabetType::MIXED;
        }
    }

    if(hasRussian)
        return AlphabetType::RUSSIAN;
    else if(hasEnglish)
        return AlphabetType::ENGLISH;
    else
        return AlphabetType::NONE;
}

bool Crypt_Alphabet_Abs::isRussianChar(QChar ch) const
{
    QChar upper = ch.toUpper();
    return russianAlphabet.contains(upper);
}

bool Crypt_Alphabet_Abs::isEnglishChar(QChar ch) const
{
    QChar upper = ch.toUpper();
    return englishAlphabet.contains(upper);
}

QString Crypt_Alphabet_Abs::filterText(const QString& text, AlphabetType alphaType, bool removeSpaces) const
{
    QString alphabet;
    switch(alphaType)
    {
    case AlphabetType::RUSSIAN:
        alphabet = russianAlphabet.toLower() + "0123456789";
        break;
    case AlphabetType::ENGLISH:
        alphabet = englishAlphabet.toLower() + "0123456789";
        break;
    default:
        return QString();
    }

    QString filtered;
    for(const QChar& ch : text)
    {
        QChar lower = ch.toLower();

        // Если символ входит в алфавит, добавляем его
        if(alphabet.contains(lower))
        {
            filtered += lower;
        }
        // Пробелы обрабатываем отдельно в зависимости от настройки
        else if(ch == ' ' && !removeSpaces)
        {
            filtered += ch;
        }
        // Все остальные символы (знаки препинания, спецсимволы) просто игнорируем
    }

    return filtered;
}
