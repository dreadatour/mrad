#ifndef __MRIM_H
#define __MRIM_H

#include "proto.h"




int mrim_connect_tcp(char *, char *);
char *to_crlf(const char *);
char *mrim_net_mklps(const char *);
char *mrim_net_mksz(char *);
void mrim_net_fill_cs_header(mrim_packet_header_t *, uint32_t, uint32_t, uint32_t);
void mrim_net_send(void *, size_t);
int mrim_net_send_flush();
int mrim_net_send_receive_ack(char *, uint32_t);
int mrim_net_send_auth_request_ack(char *);
int mrim_send_hello();
int mrim_send_auth(const char *, const char *, uint32_t);
int mrim_send_message(const char *, const char *, uint32_t);
int mrim_send_ping();
void mrim_read_message(char *, uint32_t);
int mrim_net_read_proceed();
int mrim_net_read();
int mrim_is_readable(int, int);
int mrim_connect(char *, char *, char *, char *);
int mrim_disconnect();

#endif
