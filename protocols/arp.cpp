#include "arp.h"
#include "ethernet.h"

Arp::Arp(const unsigned char *data, qsizetype size) : Protocol(data, size)
{
    int macLen=data[4];
    if (macLen > 12)
      macLen = 12;
    int ipLen=data[5];
    if (ipLen > 4)
      ipLen = 4;
    srcMac = QByteArray((const char *)data + 8, macLen).toHex(':');
    srcIP.setAddress(
        toIpv4(QByteArray((const char *)data + 8 + macLen, ipLen)));
    dstMac =
        QByteArray((const char *)data + 8 + macLen + ipLen, macLen).toHex(':');
    dstIP.setAddress(
        toIpv4(QByteArray((const char *)data + 8 + 2 * macLen + ipLen, ipLen)));
}

QString Arp::infoPrint()
{
    switch (bytes.at(7)) {
    case 0x1:
      return QString("Who has %1? Tell %2")
          .arg(dstIP.toString(), srcIP.toString());
      break;
    case 0x2:
      return QString("%1 is at %2").arg(srcIP.toString(), srcMac);
      break;
    default:
        return QString("Unknown arp package!");
        break;
    }
}

void Arp::treePrint(QTreeWidget *parent)
{
    QTreeWidgetItem *top = new QTreeWidgetItem(parent);
    quint16 type = bytes.at(7);
    if(type==0x1)
    {
        top->setText(0, QString("Address Resolution Protocol (request)"));
    }
    if(type==0x2)
    {
        top->setText(0, QString("Address Resolution Protocol (reply)"));
    }

    QTreeWidgetItem *data = new QTreeWidgetItem(top);
    type = (static_cast<quint8>(this->bytes.at(0)) << 8) |
                   static_cast<quint8>(this->bytes.at(1));
    switch (type) {
    case 0x0001:
        data->setText(0, QString("Hardware type: Ethernet (%1)").arg(type));
        break;
    default:
        data->setText(0, QString("Unknown type: (%1)").arg(type));
        break;
    }

    data = new QTreeWidgetItem(top);
    type = (static_cast<quint8>(this->bytes.at(2)) << 8) |
                   static_cast<quint8>(this->bytes.at(3));
    QString strType = Ethernet::strEtherTypes.value(type, "Unknown");
    data->setText(
        0, QString("Protocol type: %1 (0x%2)")
               .arg(strType, QString::number(type, 16).rightJustified(4, '0')));

    data = new QTreeWidgetItem(top);
    type = bytes.at(4);
    data->setText(0, QString("Hardware size: %1").arg(type));

    data = new QTreeWidgetItem(top);
    type = bytes.at(5);
    data->setText(0, QString("Protocol size: %1").arg(type));

    data = new QTreeWidgetItem(top);
    type = (static_cast<quint8>(this->bytes.at(6)) << 8) |
                   static_cast<quint8>(this->bytes.at(7));
    if(type==1)
        data->setText(0, QString("Opcode: request (%1)").arg(type));
    else if(type==2)
        data->setText(0, QString("Opcode: reply (%1)").arg(type));
    else
        data->setText(0, QString("Opcode: unknown (%1)").arg(type));

    data = new QTreeWidgetItem(top);
    data->setText(0,QString("Sender Mac Address: %1").arg(srcMac));

    data = new QTreeWidgetItem(top);
    data->setText(0,QString("Sender IP Address: %1").arg(srcIP.toString()));

    data = new QTreeWidgetItem(top);
    data->setText(0,QString("Target Mac Address: %1").arg(dstMac));

    data = new QTreeWidgetItem(top);
    data->setText(0,QString("Target IP Address: %1").arg(dstIP.toString()));
};
