#include <QApplication>

#include "MainDialog.h"
#include "Global.h"

void init();

int main(int argc, char* argv[])
{
    QApplication a(argc, argv);

    init();

    MainDialog mainDlg;
    mainDlg.show();

    return a.exec();
}

void init()
{
    Global::enableStyle();
}
