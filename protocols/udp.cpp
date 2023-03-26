#include "udp.h"

Udp::Udp(const unsigned char *data, qsizetype size) : Protocol(data, size) {
  srcPort = (static_cast<quint8>(this->bytes.at(0)) << 8) |
            static_cast<quint8>(this->bytes.at(1));
  dstPort = (static_cast<quint8>(this->bytes.at(2)) << 8) |
          static_cast<quint8>(this->bytes.at(3));
  dataLen = (static_cast<quint8>(this->bytes.at(4)) << 8) |
            static_cast<quint8>(this->bytes.at(5));
}

void Udp::treePrint(QTreeWidget *parent)
{
    QTreeWidgetItem *top = new QTreeWidgetItem(parent);
    top->setText(0,
                 QString("User Datagram Protocol, Src Port: %1, Dst Port: %2")
                     .arg(QString::number(srcPort), QString::number(dstPort)));

    QTreeWidgetItem *data = new QTreeWidgetItem(top);
    data->setText(0, QString("Source Port: %1").arg(QString::number(srcPort)));

    data = new QTreeWidgetItem(top);
    data->setText(0, QString("Destination Port: %1").arg(QString::number(dstPort)));

    data = new QTreeWidgetItem(top);
    data->setText(0, QString("Length: %1").arg(QString::number(dataLen)));

    data = new QTreeWidgetItem(top);
    quint16 type = (static_cast<quint8>(this->bytes.at(6)) << 8) |
                   static_cast<quint8>(this->bytes.at(7));
    data->setText(0, QString("Checksum: 0x%1").arg(QString::number(type,16).rightJustified(4,'0')));
}

QString Udp::infoPrint()
{
    return QString("%1 → %2  Len=%3")
        .arg(QString::number(srcPort), QString::number(dstPort),
             QString::number(dataLen));
}
