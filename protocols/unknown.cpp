#include "unknown.h"

Unknown::Unknown(const unsigned char *data, qsizetype size):Protocol(data,size)
{

}

void Unknown::treePrint(QTreeWidget *parent)
{
    QTreeWidgetItem* top=new QTreeWidgetItem(parent);
    top->setText(0, QString("Data (%1 bytes)").arg(getLen()));
    QTreeWidgetItem* data=new QTreeWidgetItem(top);
    QString s=bytes.toHex();
    data->setText(0, QString("Data: %1").arg(s));
}
