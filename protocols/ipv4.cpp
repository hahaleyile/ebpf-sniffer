#include "ipv4.h"

QMap<quint8, QString> Ipv4::strIpTypes = {
    {0x01, "ICMP"}, {0x06, "TCP"}, {0x11, "UDP"}};

Ipv4::Ipv4(const unsigned char *data, qsizetype size) : Protocol(data, size)
{
  srcIP.setAddress(toIpv4(QByteArray((const char *)data + 12, 4)));
  dstIP.setAddress(toIpv4(QByteArray((const char *)data + 16, 4)));
}

IpTypes Ipv4::getType()
{
  quint8 type = bytes.at(9);
  switch (type) {
  case 0x01:
    return IpTypes::ICMP;
  case 0x06:
    return IpTypes::TCP;
  case 0x11:
    return IpTypes::UDP;
  default:
    return IpTypes::UNKNOWN;
  }
}

void Ipv4::treePrint(QTreeWidget *parent)
{
    QTreeWidgetItem *top = new QTreeWidgetItem(parent);
    quint16 type = bytes.at(0) >> 4;
    top->setText(
        0, QString("Internet Protocol Version %1, Src: %2, Dst: %3")
               .arg(QString::number(type), srcIP.toString(), dstIP.toString()));

    QTreeWidgetItem *data = new QTreeWidgetItem(top);
    data->setText(0, QString("%1 .... = Version: %2")
                         .arg(QString::number(type, 2).rightJustified(4, '0'),
                              QString::number(type)));

    data = new QTreeWidgetItem(top);
    type = bytes.at(0) & 0xf;
    data->setText(0,
                  QString(".... %1 = Header Length: %2 bytes (%3)")
                      .arg(QString::number(type, 2).rightJustified(4, '0'),
                           QString::number(type * 5), QString::number(type)));

    data = new QTreeWidgetItem(top);
    type = (static_cast<quint8>(this->bytes.at(2)) << 8) |
                   static_cast<quint8>(this->bytes.at(3));
    data->setText(0, QString("Total Length: %1").arg(QString::number(type)));

    data = new QTreeWidgetItem(top);
    type = bytes.at(6);
    data->setText(0,
                  QString("Flags: 0x%1")
                      .arg(QString::number(type, 16).rightJustified(2, '0')));
    QString set("");
    QTreeWidgetItem *child;

    child = new QTreeWidgetItem(data);
    quint8 flag = (type >> 7) & 0x01;
    if (flag) {
      set = "";
    } else {
      set = "Not ";
    }
    child->setText(0, QString("%1... .... = Reserved bit: %2set")
                          .arg(QString::number(flag, 2), set));

    child = new QTreeWidgetItem(data);
    flag = (type >> 6) & 0x01;
    if (flag) {
      set = "";
    } else {
      set = "Not ";
    }
    child->setText(0, QString(".%1.. .... = Don't fragment: %2set")
                          .arg(QString::number(flag, 2), set));

    child = new QTreeWidgetItem(data);
    flag = (type >> 5) & 0x01;
    if (flag) {
      set = "";
    } else {
      set = "Not ";
    }
    child->setText(0, QString("..%1. .... = More fragment: %2set")
                          .arg(QString::number(flag, 2), set));

    data = new QTreeWidgetItem(top);
    type = ((static_cast<quint8>(this->bytes.at(6)) << 8) |
            static_cast<quint8>(this->bytes.at(7))) &
           0x1fff;
    data->setText(0, QString("Fragment Offset: %1").arg(QString::number(type)));

    data = new QTreeWidgetItem(top);
    type = bytes.at(8) & 0xff;
    data->setText(0, QString("Time to Live: %1").arg(QString::number(type)));

    data = new QTreeWidgetItem(top);
    type = bytes.at(9) & 0xff;
    data->setText(
        0, QString("Protocol: %1 (%2)")
               .arg(strIpTypes.value(type, "Unknown"), QString::number(type)));

    data = new QTreeWidgetItem(top);
    type = (static_cast<quint8>(this->bytes.at(10)) << 8) |
                   static_cast<quint8>(this->bytes.at(11));
    data->setText(0,
                  QString("Header Checksum: 0x%1 [Validation disabled]")
                      .arg(QString::number(type, 16).rightJustified(4, '0')));

    data = new QTreeWidgetItem(top);
    data->setText(0, QString("Source Address: %1").arg(srcIP.toString()));

    data = new QTreeWidgetItem(top);
    data->setText(0, QString("Destination Address: %1").arg(dstIP.toString()));
}
