#include "mainwindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    QFont appFont("Consolas", 12); // 12-ый размер шрифта для всего проекта (кроме тех мест где я прописывал все вручную)
    a.setFont(appFont);
    MainWindow w;
    w.show();
    return a.exec();
}
