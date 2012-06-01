#ifndef __MRIM_H
#define __MRIM_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include "proto.h"

#define BUF_LEN 65536


int socket_open_tcp(unsigned int);
int socket_is_readable(int, int);
int socket_read();
int socket_open(unsigned int);
int socket_close();

#endif
