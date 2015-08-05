#ifndef AESASYNC_H
#define AESASYNC_H

#include <QThread>
#include "AESCipher.h"

class AESAsync : public QThread
{
    Q_OBJECT
public:
    AESAsync();

    void EnDeCrypt(const QString& fileName, const QString& key);
    void encrypt(const QString& str, const QString& key);
    void decrypt(const QString& str, const QString& key);

protected:
    void run() override;

private:
    enum Operation { FILE_EN_DE, TEXT_ENCRYPT, TEXT_DECRYPT };

    AESCipher mAES;
    Operation mO;
    QString   mFileName;
    QString   mStr;
    QString   mKey;

signals:
    void fileCryptResult(bool);
    void textCryptResult(QString);
};

#endif
