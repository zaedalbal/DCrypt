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
