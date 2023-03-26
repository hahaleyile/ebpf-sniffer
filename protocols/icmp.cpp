#include "icmp.h"

QMap<quint8, QString> Icmp::strIcmpTypes = {{0x00, "Echo (ping) reply"},
                                            {0x03, "Destination Unreachable"},
                                            {8, "Echo (ping) request"}};

Icmp::Icmp(const unsigned char *data, qsizetype size) : Protocol(data, size)
{
  id = (static_cast<quint8>(this->bytes.at(4)) << 8) |
       static_cast<quint8>(this->bytes.at(5));
  seq = (static_cast<quint8>(this->bytes.at(6)) << 8) |
        static_cast<quint8>(this->bytes.at(7));
}

void Icmp::treePrint(QTreeWidget *parent)
{
    QTreeWidgetItem *top = new QTreeWidgetItem(parent);
    top->setText(0, "Internet Control Message Protocol");

    QTreeWidgetItem *data = new QTreeWidgetItem(top);
    quint16 type = bytes.at(0) & 0xf;
    data->setText(0, QString("Type: %1 (%2)")
                         .arg(QString::number(type), strIcmpTypes.value(type, "Unknown")));

    data = new QTreeWidgetItem(top);
    type = bytes.at(1) & 0xf;
    data->setText(0, QString("Code: %1").arg(QString::number(type)));

    data = new QTreeWidgetItem(top);
    type = (static_cast<quint8>(this->bytes.at(2)) << 8) |
           static_cast<quint8>(this->bytes.at(3));
    data->setText(0,
                  QString("Checksum: 0x%1")
                      .arg(QString::number(type, 16).rightJustified(4, '0')));

    data = new QTreeWidgetItem(top);
    data->setText(0, QString("Identifier: %1").arg(QString::number(id)));

    data = new QTreeWidgetItem(top);
    data->setText(0, QString("Sequence Number: %1").arg(QString::number(seq)));

    data = new QTreeWidgetItem(top);
    data->setText(
        0, QString("Data (%1 bytes)").arg(QString::number(getLen() - 8)));

    QTreeWidgetItem *child=new QTreeWidgetItem(data);
    child->setText(0,QString("Data: %1").arg(bytes.mid(8).toHex()));
}

QString Icmp::infoPrint()
{
    quint8 type = bytes.at(0);
    return QString("%1  id=0x%2, seq=0x%3")
        .arg(strIcmpTypes.value(type, "Unknown ICMP package type"),
             QString::number(id).rightJustified(4, '0'),
             QString::number(seq).rightJustified(4, '0'));
}
