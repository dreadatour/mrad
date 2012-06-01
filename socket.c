#include "socket.h"
#include <unistd.h>
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
static int input_socket = -1;          // socket to listen input messages on
static char *input_buf;                // input buffer
//TODO not used static unsigned int input_len;         // input buffer size

/*******************************************************************************
	Open TCP socket
*******************************************************************************/
int
socket_open_tcp(unsigned int port)
{
	int s;
	struct sockaddr_in sin;

	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1 && errno != EINTR) {
		syslog(LOG_ERR, "cannot create socket: %s", strerror(errno));
		return -1;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(port);

	if (bind(s, (struct sockaddr *) &sin, sizeof(sin)) == -1 && errno != EINTR) {
		syslog(LOG_ERR, "cannot bind socket: %s", strerror(errno));
		return -1;
	}

	if (listen(s, 5) == -1 && errno != EINTR) {
		syslog(LOG_ERR, "cannot listen socket: %s", strerror(errno));
		return -1;
	}

	return s;
}

/*******************************************************************************
	Check if data from local socket is exists
*******************************************************************************/
int
socket_is_readable(int timeout_sec, int timeout_usec)
{
	struct timeval tv;
	fd_set rset;
	int isready;

	FD_ZERO(&rset);
	FD_SET(input_socket, &rset);

	tv.tv_sec  = timeout_sec;
	tv.tv_usec = timeout_usec;

again:
	isready = select(input_socket + 1, &rset, NULL, NULL, &tv);
	if (isready < 0) {
		if (errno == EINTR) goto again;
		syslog(LOG_ERR, "error on select socket: %s", strerror(errno));
		return -1;
	}

	return isready;
}

/*******************************************************************************
	Read data from local socket
*******************************************************************************/
int
socket_read()
{
	int in;
	struct sockaddr_in clientname;
	socklen_t size;
	char buf[BUF_LEN];
	char *to, *msg, *p;
	int len, to_len;

	size = sizeof(clientname);
	in = accept(input_socket, (struct sockaddr *) &clientname, &size);
	if (in < 0 && errno != EINTR) {
		syslog(LOG_ERR, "cannot accept socket: %s", strerror(errno));
		return -1;
	}

	// read data from socket
	len = read(in, buf, BUF_LEN);
	close(in);
	
	syslog(LOG_DEBUG, "Readed from local socket, bytes: %d", len);

	if (len < 0 && errno != EINTR) {
		syslog(LOG_ERR, "cannot read data from socket: %s", strerror(errno));
		return -1;
	}
	buf[len] = '\0';
	syslog(LOG_INFO, "raw data: '%s'", buf);

	msg = strstr(buf, "\n");
	if (msg) {
		to_len = msg - buf;
		to = (char *) malloc(to_len + 1);
		memcpy(to, buf, to_len);
		to[to_len] = '\0';
		msg++;

		p = strtok(to, " ,");
		while (p != NULL) {
			syslog(LOG_INFO, "send message to '%s': '%s'", p, msg);
			mrim_send_message(p, msg, 0);
			p = strtok (NULL, " ,");
		}

		free(to);
	} else {
		syslog(LOG_ERR, "cannot find 'to' and 'text' here: %s", buf);
	}
}

/*******************************************************************************
	Open input socket
*******************************************************************************/
int
socket_open(unsigned int port)
{
	syslog(LOG_DEBUG, "Setup listen connections on port %d", port);

	if (input_socket > 0) {
		close(input_socket);
	}
	
	if ((input_socket = socket_open_tcp(port)) == -1) {
		syslog(LOG_ERR, "cannot open port %d", port);
		return -1;
	}

	return 0;
}

/*******************************************************************************
	Close input socket
*******************************************************************************/
int
socket_close()
{
	syslog(LOG_DEBUG, "Close input socket");
	
	free(input_buf);
	if (input_socket > 0) {
		close(input_socket);
	}
}

