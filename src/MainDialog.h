#ifndef MAINDIALOG_H
#define MAINDIALOG_H

#include <QDialog>
#include <QFileDialog>
#include <QTabWidget>
#include <QLabel>
#include <QLineEdit>
#include <QTextEdit>
#include <QCheckBox>
#include <QPushButton>

#include <QVBoxLayout>
#include <QHBoxLayout>

#include "qlightboxwidget.h"
#include "KeyLineValidator.h"
#include "AESAsync.h"

class MainDialog : public QDialog
{
    Q_OBJECT
public:
    explicit MainDialog(QWidget* parent = 0);

private:
    void initTextTab();
    void initFileTab();

    void initLightBox();
    void showLightBox(const QString& msg, const QString& color, bool showOkButton = true);

    // "open" file "fileName"
    void openFile(const QString& fileName);

    // AES cipher
    AESAsync         mAES;
    // opened file name
    QString          mFileName = "";

    // ui controls
    QTabWidget*      mTabWidget;
    // light box
    QLightBoxWidget* mLightBox;
    QLabel*          mMsgLabel;
    QPushButton*     mOkButton;
    // text tab
    QTextEdit*       mTextEdit;
    QLabel*          mT1KeyLabel;
    QCheckBox*       mT1ShowKeyCheckBox;
    QLineEdit*       mT1KeyLine;
    QPushButton*     mEncryptButton;
    QPushButton*     mDecryptButton;
    // file tab
    QLineEdit*       mFileNameLine;
    QPushButton*     mOpenButton;
    QLabel*          mT2KeyLabel;
    QCheckBox*       mT2ShowKeyCheckBox;
    QLineEdit*       mT2KeyLine;
    QPushButton*     mEnDeButton;

public slots:
    void openButtonClick();
    void showCheckBoxClick(bool checked);
    void encryptButtonClick();
    void decryptButtonClick();
    void endeButtonClick();
    // encrypt/decrypt result
    void textEnDeResult(QString result);
    void fileEnDeResult(bool result);
    // show wait dialog
    void showProcess();
};

#endif
