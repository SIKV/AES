#ifndef GLOBAL_H
#define GLOBAL_H

#include <QApplication>
#include <QFile>
#include <QTextStream>
#include <QFontDatabase>

class Global
{
private:
    Global() { }
public:
    static void enableStyle()
    {
        QFile sheetFile(":/res/style.qss");

        if (sheetFile.exists()) {
            sheetFile.open(QFile::ReadOnly | QFile::Text);
            QTextStream textStream(&sheetFile);
            qApp->setStyleSheet(textStream.readAll());
        }
    }
};

#endif
