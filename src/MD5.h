#ifndef MD5_H
#define MD5_H

#include <QCryptographicHash>
#include <QString>

class MD5
{
private:
    MD5();
public:
    // returns MD5(str)
    static std::string hash(const std::string& str)
    {
        QByteArray ba = QString::fromStdString(str).toLatin1();
        QByteArray hash = QCryptographicHash::hash(ba, QCryptographicHash::Md5);

        std::string res = "";
        for (char c : hash)
            res += c;

        return res;
    }
};

#endif
