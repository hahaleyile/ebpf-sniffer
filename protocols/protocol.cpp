#include "protocol.h"

Protocol::Protocol(const unsigned char *data, qsizetype size):len(size),bytes(reinterpret_cast<const char*>(data),size) {
}


Protocol::~Protocol(){
}

QString Protocol::infoPrint(){
    return QString();
}


QString toIpv4(QByteArray &&bytes)
{
    QString result;
    if (bytes.size() != 4)
      return result;

    for (int i = 0; i < 4; ++i) {
      result.append(QString::number((unsigned char)bytes.at(i)));
      if (i < 3)
        result.append(".");
    }
    return result;
}
