#ifndef PADDING_H
#define PADDING_H

#include "protocol.h"

class Padding : public Protocol
{
public:
    Padding(const unsigned char *data, qsizetype size);
};

#endif // PADDING_H
