#include "AESAsync.h"

AESAsync::AESAsync()
{
}

void AESAsync::EnDeCrypt(const QString &fileName, const QString &key)
{
    mFileName = fileName;
    mKey      = key;

    mO = Operation::FILE_EN_DE;
    start();
}

void AESAsync::encrypt(const QString &str, const QString &key)
{
    mStr = str;
    mKey = key;

    mO = Operation::TEXT_ENCRYPT;
    start();
}

void AESAsync::decrypt(const QString &str, const QString &key)
{
    mStr = str;
    mKey = key;

    mO = Operation::TEXT_DECRYPT;
    start();
}

void AESAsync::run()
{
    if (mO == Operation::FILE_EN_DE)
    {
        bool res = mAES.EnDeCrypt(mFileName.toStdString(), mKey.toStdString());
        emit fileCryptResult(res);
    }
    else if (mO == Operation::TEXT_ENCRYPT)
    {
        QString res = QString::fromStdString(
                    mAES.encrypt(mStr.toStdString(), mKey.toStdString()));
        emit textCryptResult(res);
    }
    else
    {
        QString res = QString::fromStdString(
                    mAES.decrypt(mStr.toStdString(), mKey.toStdString()));
        emit textCryptResult(res);
    }
}
