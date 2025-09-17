#include "mainwindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    QFont appFont("Consolas", 12);
    a.setFont(appFont);
    MainWindow w;
    w.show();
    return a.exec();
}
