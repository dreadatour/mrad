#ifndef __MRIM_H
#define __MRIM_H



int socket_open_tcp(unsigned int);
int socket_is_readable(int, int);
int socket_read();
int socket_open(unsigned int);
int socket_close();

#endif
