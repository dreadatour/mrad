#ifndef __SOCKET_H
#define __SOCKET_H



int socket_open_tcp(unsigned int);
int socket_is_readable(int, int);
int socket_read();
int socket_open(unsigned int);
int socket_close();

#endif
