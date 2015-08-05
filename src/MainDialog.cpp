#include "MainDialog.h"

#include <QDebug>

MainDialog::MainDialog(QWidget* parent):
    QDialog(parent)
{
    // creating
    mTabWidget = new QTabWidget;

    // add tabs
    initTextTab();
    initFileTab();

    initLightBox();

    // main layout
    setLayout(new QVBoxLayout);

    layout()->addWidget(mTabWidget);
    layout()->setMargin(1);

    // dialog's properties
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);
    setWindowIcon(QIcon(":/res/icon.ico"));
    setWindowTitle("Advanced Encryption Standard");
    setMaximumSize(500, 500);
    resize(400, 0);

    // connects
    connect(mOpenButton,        SIGNAL(clicked()),                this, SLOT(openButtonClick()));
    connect(mT1ShowKeyCheckBox, SIGNAL(clicked(bool)),            this, SLOT(showCheckBoxClick(bool)));
    connect(mT2ShowKeyCheckBox, SIGNAL(clicked(bool)),            this, SLOT(showCheckBoxClick(bool)));
    connect(mEncryptButton,     SIGNAL(clicked()),                this, SLOT(encryptButtonClick()));
    connect(mDecryptButton,     SIGNAL(clicked()),                this, SLOT(decryptButtonClick()));
    connect(mEnDeButton,        SIGNAL(clicked()),                this, SLOT(endeButtonClick()));

    connect(&mAES,              SIGNAL(started()),                this, SLOT(showProcess()));
    connect(&mAES,              SIGNAL(fileCryptResult(bool)),    this, SLOT(fileEnDeResult(bool)));
    connect(&mAES,              SIGNAL(textCryptResult(QString)), this, SLOT(textEnDeResult(QString)));
}

void MainDialog::initTextTab()
{
    // widget for a tab
    QWidget* wgt       = new QWidget;
    // creating
    mTextEdit          = new QTextEdit(tr("Enter your text here."));
    mT1KeyLabel        = new QLabel(tr("Key"));
    mT1ShowKeyCheckBox = new QCheckBox(tr("Show Key"));
    mT1KeyLine         = new QLineEdit(tr("secret_key"));
    mEncryptButton     = new QPushButton(tr("Encrypt"));
    mDecryptButton     = new QPushButton(tr("Decrypt"));

    // set properties
    mT1ShowKeyCheckBox->setCursor(Qt::PointingHandCursor);
    mT1ShowKeyCheckBox->setChecked(true);

    mT1KeyLine->setValidator(new KeyLineValidator(mT1KeyLine));
    mT1KeyLine->setMaxLength(256);

    mEncryptButton->setCursor(Qt::PointingHandCursor);
    mDecryptButton->setCursor(Qt::PointingHandCursor);

    // layouts
    QHBoxLayout* keyLayout = new QHBoxLayout;
    keyLayout->addWidget(mT1KeyLabel);
    keyLayout->addWidget(mT1ShowKeyCheckBox, 0, Qt::AlignRight);

    QHBoxLayout* btnLayout = new QHBoxLayout;
    btnLayout->addWidget(mEncryptButton);
    btnLayout->addWidget(mDecryptButton);

    // main layout
    QVBoxLayout* mainLayout = new QVBoxLayout;

    mainLayout->addWidget(mTextEdit);
    mainLayout->addLayout(keyLayout);
    mainLayout->addWidget(mT1KeyLine);
    mainLayout->addLayout(btnLayout);

    wgt->setLayout(mainLayout);

    // add tab
    mTabWidget->addTab(wgt, tr("Text"));
}

void MainDialog::initFileTab()
{
    // widget for a tab
    QWidget* wgt       = new QWidget;
    // creating
    mFileNameLine      = new QLineEdit(tr("choose_file"));
    mOpenButton        = new QPushButton(". . .");
    mT2KeyLabel        = new QLabel(tr("Key"));
    mT2ShowKeyCheckBox = new QCheckBox(tr("Show Key"));
    mT2KeyLine         = new QLineEdit(tr("secret_key"));
    mEnDeButton        = new QPushButton(tr("Encrypt / Decrypt"));

    // set properties
    mFileNameLine->setObjectName("FileNameLine");
    mFileNameLine->setReadOnly(true);

    mOpenButton->setCursor(Qt::PointingHandCursor);

    mT2ShowKeyCheckBox->setCursor(Qt::PointingHandCursor);
    mT2ShowKeyCheckBox->setChecked(true);

    mT2KeyLine->setValidator(new KeyLineValidator(mT2KeyLine));
    mT2KeyLine->setMaxLength(256);

    mEnDeButton->setCursor(Qt::PointingHandCursor);

    // layouts
    QHBoxLayout* fileLayout = new QHBoxLayout;
    fileLayout->addWidget(mFileNameLine, 1);
    fileLayout->addWidget(mOpenButton, 0);

    QHBoxLayout* keyLayout = new QHBoxLayout;
    keyLayout->addWidget(mT2KeyLabel);
    keyLayout->addWidget(mT2ShowKeyCheckBox, 0, Qt::AlignRight);

    // main layout
    QVBoxLayout* mainLayout = new QVBoxLayout;

    mainLayout->addLayout(fileLayout);
    mainLayout->addLayout(keyLayout);
    mainLayout->addWidget(mT2KeyLine);
    mainLayout->addWidget(mEnDeButton);

    wgt->setLayout(mainLayout);

    // add tab
    mTabWidget->addTab(wgt, tr("File"));
}

void MainDialog::initLightBox()
{
    mLightBox = new QLightBoxWidget(this);
    mMsgLabel = new QLabel;
    mOkButton = new QPushButton(tr("OK"));

    mMsgLabel->setObjectName("MsgLabel");
    mOkButton->setCursor(Qt::PointingHandCursor);

    QVBoxLayout* lightBoxLayout = new QVBoxLayout;

    lightBoxLayout->addWidget(mMsgLabel, 0, Qt::AlignCenter);
    lightBoxLayout->addWidget(mOkButton, 0, Qt::AlignRight);

    mLightBox->setLayout(lightBoxLayout);

    connect(mOkButton, SIGNAL(clicked()), mLightBox, SLOT(close()));
}

void MainDialog::showLightBox(const QString& msg, const QString& color, bool showOkButton)
{
    mMsgLabel->setStyleSheet("QLabel { background-color: " + color + "; }");
    mMsgLabel->setText(msg);
    mOkButton->setVisible(showOkButton);

    mLightBox->show();
}

void MainDialog::openFile(const QString &fileName)
{
    // set opened file name to mFileName
    mFileName = fileName;
    mFileNameLine->setText(QFileInfo(mFileName).fileName());
    // tool tip shows full fileName
    mFileNameLine->setToolTip(mFileName);

    // if fileName is encrypted, button text = Decrypt else Encrypt
    if (AESCipher::is_encrypted(mFileName.toStdString()))
        mEnDeButton->setText(tr("Decrypt"));
    else
        mEnDeButton->setText(tr("Encrypt"));
}

///////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////// SLOTS /////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////

void MainDialog::openButtonClick()
{
    // open file dialog
    QString fileName = QFileDialog::getOpenFileName(this);

    if (!fileName.isEmpty())
        openFile(fileName);
}

void MainDialog::showCheckBoxClick(bool checked)
{
    QLineEdit* keyLine;

    if (sender() == mT1ShowKeyCheckBox)
        keyLine = mT1KeyLine;
    else
        keyLine = mT2KeyLine;

    if (checked)
        keyLine->setEchoMode(QLineEdit::Normal);
    else
        keyLine->setEchoMode(QLineEdit::Password);
}

void MainDialog::encryptButtonClick()
{
    mAES.encrypt(mTextEdit->toPlainText().trimmed(), mT1KeyLine->text());
}

void MainDialog::decryptButtonClick()
{
    mAES.decrypt(mTextEdit->toPlainText().trimmed(), mT1KeyLine->text());
}

void MainDialog::endeButtonClick()
{
    mAES.EnDeCrypt(mFileName, mT2KeyLine->text());
}

void MainDialog::textEnDeResult(QString result)
{
    mLightBox->hide();
    mTextEdit->setText(result);
}

void MainDialog::fileEnDeResult(bool result)
{
    if (result)
    {
        showLightBox(tr("SUCCESS"), "green");
        openFile(QString::fromStdString(AESCipher::inv_file_name(mFileName.toStdString())));
    }
    else
        showLightBox(tr("FAILURE"), "red");
}

void MainDialog::showProcess()
{
    showLightBox(tr("PLEASE WAIT..."), "black", false);
}
