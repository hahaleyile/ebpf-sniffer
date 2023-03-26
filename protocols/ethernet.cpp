#include "ethernet.h"

QMap<quint16, QString> Ethernet::strEtherTypes = {{0x0800, "IPV4"},
                                                  {0x86DD, "IPV6"},
                                                  {0x0806, "ARP"}};

Ethernet::Ethernet(const unsigned char *data, qsizetype size)
    : Protocol(data, size),
      dstMac(QByteArray((const char *)data, 6).toHex(':')),
      srcMac(QByteArray((const char *)data + 6, 6).toHex(':')) {}

void Ethernet::treePrint(QTreeWidget *parent) {
  QTreeWidgetItem *top = new QTreeWidgetItem(parent);
  top->setText(0, QString("Ethernet II, Src: %1, Dst: %2").arg(srcMac, dstMac));

  QTreeWidgetItem *data = new QTreeWidgetItem(top);
  data->setText(0, QString("Destination: %1").arg(dstMac));

  data = new QTreeWidgetItem(top);
  data->setText(0, QString("Source: %1").arg(srcMac));

  data = new QTreeWidgetItem(top);
  quint16 type = (static_cast<quint8>(this->bytes.at(12)) << 8) |
                 static_cast<quint8>(this->bytes.at(13));
  QString strType = strEtherTypes.value(type, "Unknown");
  data->setText(
      0, QString("Type: %1 (0x%2)")
             .arg(strType, QString::number(type, 16).rightJustified(4, '0')));

  if (hasPadding) {
    data = new QTreeWidgetItem(top);
    QString s=bytes.mid(14).toHex();
    data->setText(0, QString("Padding: %1").arg(s));
  }
}

EtherTypes Ethernet::getType() {
  quint16 type = (static_cast<quint8>(this->bytes.at(12)) << 8) |
                 static_cast<quint8>(this->bytes.at(13));
  switch (type) {
  case 0x0800:
    return EtherTypes::IPV4;
  case 0x86DD:
    return EtherTypes::IPV6;
  case 0x0806:
    return EtherTypes::ARP;
  default:
    return EtherTypes::UNKNOWN;
  }
}

void Ethernet::addPadding(const char *data, qsizetype size)
{
    bytes.append(data,size);
    hasPadding = true;
}
