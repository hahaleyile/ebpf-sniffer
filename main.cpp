#include "mainwindow.h"

#include <QApplication>
MainWindow *w;

int main(int argc, char *argv[])
{
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling); // DPI support
    QCoreApplication::setAttribute(Qt::AA_UseHighDpiPixmaps); // HiDPI pixmaps
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}
