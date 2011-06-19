#ifndef __MRIM_H
#define __MRIM_H

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include "proto.h"

#define VERSION_TXT "mrad 0.1"
#define MRA_BUF_LEN     65536

#define LPSLENGTH(s) (*((uint32_t *)(s)))
#define LPSSIZE(s)   (LPSLENGTH(s) + sizeof(uint32_t))
#define LPSALLOC(c)  ((char *) malloc((c) + sizeof(uint32_t)))

int mra_socket = -1;            // mra socket
char *tx_buf;                   // TX buffer
unsigned int tx_len;            // TX buffer size
char *rx_buf;                   // RX buffer
unsigned int rx_len;            // RX buffer size
unsigned int seq = 0;           // Sequence number

int received_hello_ack = 0;     // Is 'hello' message received
int received_login_ack = 0;     // Is 'login OK' message recievied
int received_login_rej = 0;     // Is 'login FAIL' message received

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
void mrim_send_ping();
void mrim_read_message(char *, uint32_t);
int mrim_net_read_proceed();
int mrim_net_read();
int mrim_is_readable(int, int);
int mrim_connect(char *, char *, char *, char *);
int mrim_disconnect();

#endif
