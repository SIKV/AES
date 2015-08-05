#ifndef KEYLINEVALIDATOR_H
#define KEYLINEVALIDATOR_H

#include <QValidator>

class KeyLineValidator : public QValidator
{
    Q_OBJECT
public:
    explicit KeyLineValidator(QObject* parent = 0):
        QValidator(parent)
    { }

    State validate(QString& str, int& pos) const override
    {
        QRegExp rxp = QRegExp("[А-Яа-я\\s]");

        return str.contains(rxp) ? Invalid : Acceptable;
    }
};

#endif
