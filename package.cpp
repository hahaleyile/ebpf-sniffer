#include "package.h"
#include "protocols/ethernet.h"
#include "protocols/icmp.h"
#include "protocols/ipv4.h"
#include "protocols/padding.h"
#include "protocols/unknown.h"
#include "protocols/arp.h"
#include <linux/types.h>
#include "xdppass.h"

Package::Package(struct packet_info *pkt_info) : len(pkt_info->len) {
  // check 802.3
  int remainSize = pkt_info->len;
  if (remainSize > 13 && pkt_info->data[12] < 0x6) {
    qDebug("Not a 802.3 header!\n");
    protocols.append(new Unknown(pkt_info->data, pkt_info->len));
    return;
  }

  remainSize-=14;
  Ethernet *e = new Ethernet(pkt_info->data, 14);
  protocols.append(e);
  src = e->getSrc();
  if(src=="ff:ff:ff:ff:ff:ff")
    src = "Broadcast";
  dst = e->getDst();
  if(dst=="ff:ff:ff:ff:ff:ff")
    dst = "Broadcast";
  lastProtocol=protocols.last();
  if (remainSize) {
    quint8 l;
    Ipv4* ip;
    switch (e->getType()) {
    case EtherTypes::ARP:
      l = 8 + 2 * (pkt_info->data[14 + 4] + pkt_info->data[14 + 5]);
      protocols.append(new Arp(pkt_info->data + 14, l));
      remainSize -= l;
      if(remainSize>0)
      {
          Ethernet* p=dynamic_cast<Ethernet*>(lastProtocol);
          lastProtocol = protocols.last();
          if(p)
          {
            p->addPadding((const char *)pkt_info->data + 14 + l, remainSize);
            protocols.append(new Padding(pkt_info->data + 14 + l, remainSize));
          }
          // TODO: error hint
      }
      else
          lastProtocol = protocols.last();
      break;

    case EtherTypes::IPV4:
      l = pkt_info->data[14] & 0xf;
      l *= 4;
      ip = new Ipv4(pkt_info->data + 14, l);
      protocols.append(ip);
      remainSize -= l;
      lastProtocol = protocols.last();
      src = ip->getSrc();
      dst = ip->getDst();
      if(remainSize>0)
      {
          switch (ip->getType()) {
          case IpTypes::ICMP:
            protocols.append(new Icmp(pkt_info->data + 14 + l, remainSize));
            lastProtocol = protocols.last();
            break;
          default:
              protocols.append(
                  new Unknown(pkt_info->data + 14 + l, remainSize));
              break;
          }
      }
      break;

    default:
      protocols.append(new Unknown(pkt_info->data + 14, pkt_info->len - 14));
      break;
    }
  }
}

QString Package::hexDump() {
  QString result;
  // 90 len
  // calculate 270-1+11*2=291
  // 11 line plus 2 bytes, 26 bytes 1 line, correct
  // 92 len to 297
  // 93 len to 302
  int requiredSize = 3 * len - 1 + ((len - 1) / 4 + 1) / 2 * 2;
  result.reserve(requiredSize);
  int i = 0;
  for (auto &protocol : protocols) {
    const char *bytes = protocol->getData();
    int size = protocol->getLen();
    for (int j = 0; j < size; ++j) {
      int t = (bytes[j] >> 4) & 0xf;
      if (t <= 9)
        result.append(QChar(t + '0'));
      else
        result.append(QChar(t + 'A' - 10));

      t = bytes[j] & 0xf;
      if (t <= 9)
        result.append(QChar(t + '0'));
      else
        result.append(QChar(t + 'A' - 10));

      i++;
      if (i == len)
        break;
      if (i % 8 == 0)
        result.append('\n');
      else if (i % 4 == 0)
        result.append(" \342\200\242 ");
      else
        result.append(' ');
    }
  }
  return result;
}

QString Package::asciiDump() {
  QString result;
  int requiredSize = len + (len - 1) / 4;
  result.reserve(requiredSize);
  int i = 0;
  for (auto &protocol : protocols) {
    const char *bytes = protocol->getData();
    int size = protocol->getLen();
    for (int j = 0; j < size; ++j) {
      if (bytes[j] < 127 && bytes[j] > 31)
        result.append(QChar(bytes[j]));
      else
        result.append("\302\267");
      i++;
      if (i == len)
        break;
      if (i % 8 == 0)
        result.append('\n');
      else if (i % 4 == 0)
        result.append(' ');
    }
  }
  return result;
}

void Package::treePrint(QTreeWidget *parent)
{
    for(auto &protocol:protocols)
    protocol->treePrint(parent);
}
