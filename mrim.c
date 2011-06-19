#include "mrim.h"

/*******************************************************************************
	Connect TCP socket
*******************************************************************************/
int
mrim_connect_tcp(char *host, char *port)
{
	int s;
	struct addrinfo hints, *res;

	if ((s = socket(PF_INET, SOCK_STREAM, 0)) == -1 && errno != EINTR) {
		syslog(LOG_ERR, "cannot create socket: %s", strerror(errno));
		return -1;
	}
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = 0;
	if (getaddrinfo(host, port, &hints, &res) != 0 && errno != EINTR) {
		syslog(LOG_ERR, "cannot getaddrinfo for %s:%s: %s", host, port, strerror(errno));
		close(s);
		return -1;
	}
	connect(s, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return s;
}

/*******************************************************************************
    Add '\r' before '\n'
*******************************************************************************/
char *
to_crlf(const char *text)
{
	size_t n = 0;
	const char *p;
	char *res;
	char *r;

	for (p = text; *p; p++) {
		if(*p == '\n' && *(p - 1) != '\r') n++;
	}
	res = (char *) malloc(strlen(text) + n);
	for (p = text, r = res; *p; p++) {
		if (*p == '\n' && *(p - 1) != '\r') {
			*r++ = '\r';
		}
		*r++ = *p;
	}
	return res;
}

/*******************************************************************************
	String -> LPS string
*******************************************************************************/
char *
mrim_net_mklps(const char *sz)
{
	uint32_t len;
	char *lps = LPSALLOC(strlen(sz));

	len = strlen(sz);
	*((uint32_t *)lps) = len;
	memcpy(lps + sizeof(uint32_t), sz, strlen(sz));
	return lps;
}

/*******************************************************************************
	LPS string -> String
*******************************************************************************/
char *
mrim_net_mksz(char *lps)
{
	uint32_t len;
	char *sz = (char *) malloc(1 + LPSLENGTH(lps));

	len = *((uint32_t *)lps);
	memcpy(sz, lps + sizeof(uint32_t), len);
	*(sz + len) = 0;
	return sz;
}

/*******************************************************************************
	Fill mrim packet header
*******************************************************************************/
void
mrim_net_fill_cs_header(mrim_packet_header_t *head, uint32_t seq, uint32_t msg, uint32_t len)
{
	head->proto    = PROTO_VERSION;
	head->magic    = CS_MAGIC;
	head->seq      = seq;
	head->msg      = msg;
	head->dlen     = len;
	head->from     = 0;
	head->fromport = 0;
}

/*******************************************************************************
	Fill RX buffer
*******************************************************************************/
void
mrim_net_send(void *data, size_t len)
{
	tx_buf = (char *) realloc(tx_buf, tx_len + len);
	memcpy(tx_buf + tx_len, data, len);
	tx_len += len;
}

/*******************************************************************************
	Do send RX buffer
*******************************************************************************/
int
mrim_net_send_flush()
{
	if (write(mra_socket, tx_buf, tx_len) == -1 && errno != EINTR) {
		syslog(LOG_ERR, "cannot write data to socket: %s (%d)", strerror(errno), errno);
		return -1;
	} else {
		tx_buf = '\0';
		tx_len = 0;
		return 0;
	}
}

/*******************************************************************************
	Send 'receive ack' packet
*******************************************************************************/
int
mrim_net_send_receive_ack(char *from, uint32_t msg_id)
{
	mrim_packet_header_t head;
	char *from_lps = mrim_net_mklps(from);

	mrim_net_fill_cs_header(&head, seq++, MRIM_CS_MESSAGE_RECV, LPSSIZE(from_lps) + sizeof(msg_id));
	mrim_net_send(&head,    sizeof(head));
	mrim_net_send(from_lps, LPSSIZE(from_lps));
	mrim_net_send(&msg_id,  sizeof(msg_id));
	free(from_lps);
	
	if (mrim_net_send_flush() == -1) {
		return -1;
	}
	return 0;
}

/*******************************************************************************
	Send 'auth ack' packet
*******************************************************************************/
int
mrim_net_send_auth_request_ack(char *email)
{
    mrim_packet_header_t head;
    char *email_lps = mrim_net_mklps(email);

    mrim_net_fill_cs_header(&head, seq++, MRIM_CS_AUTHORIZE, LPSSIZE(email_lps));
    mrim_net_send(&head,  sizeof(head));
    mrim_net_send(email_lps, LPSSIZE(email_lps));
	free(email_lps);
	
	if (mrim_net_send_flush() == -1) {
		return -1;
	}
	return 0;
}

/*******************************************************************************
	Send 'hello' packet
*******************************************************************************/
int
mrim_send_hello()
{
	mrim_packet_header_t head;

	mrim_net_fill_cs_header(&head, seq++, MRIM_CS_HELLO, 0);
	mrim_net_send(&head, sizeof(head));
	if (mrim_net_send_flush() == -1) {
		return -1;
	}

	while (received_hello_ack == 0) {
		if (mrim_net_read() == -1) {
			return -1;
		}
	}

	return 0;
}

/*******************************************************************************
	Send 'auth' packet
*******************************************************************************/
int
mrim_send_auth(const char *username, const char *password, uint32_t status)
{
	mrim_packet_header_t head;
	char *username_lps;
	char *password_lps;
	char *desc_lps;
	uint32_t dw = 0;
	size_t i;

	// convert username, password and desc to LPS
	username_lps = mrim_net_mklps(username);
	password_lps = mrim_net_mklps(password);
	desc_lps     = mrim_net_mklps(VERSION_TXT);

	// send all data
	mrim_net_fill_cs_header(&head, seq++, MRIM_CS_LOGIN2, LPSSIZE(username_lps) + LPSSIZE(password_lps) + LPSSIZE(desc_lps) + sizeof(uint32_t) * 6);
	mrim_net_send(&head,        sizeof(head));
	mrim_net_send(username_lps, LPSSIZE(username_lps));
	mrim_net_send(password_lps, LPSSIZE(password_lps));
	mrim_net_send(&status,      sizeof(status));
	mrim_net_send(desc_lps,     LPSSIZE(desc_lps));
	for (i = 0; i < 5; i++) {
		mrim_net_send(&dw,      sizeof(dw));
	}
	free(username_lps);
	free(password_lps);
	free(desc_lps);

	if (mrim_net_send_flush() == -1) {
		return -1;
	}

	while (received_login_ack == 0 && received_login_rej == 0) {
		if (mrim_net_read() == -1) {
			return -1;
		}
	}

	return 0;
}

/*******************************************************************************
	Send 'message' packet
*******************************************************************************/
int
mrim_send_message(const char *to, const char *message, uint32_t flags)
{
	mrim_packet_header_t head;
	char *to_lps;
	char *message_lps;
	char *message_rtf_lps;
	int ret;

	to_lps = mrim_net_mklps(to);
//	message_lps = mrim_net_mklps(to_crlf(utf8_to_cp1251(message)));
	message_lps = mrim_net_mklps(to_crlf(message));
//	message_rtf_lps = mrim_net_mklps(to_crlf(utf8_to_cp1251(" ")));
	message_rtf_lps = mrim_net_mklps(to_crlf(" "));

	mrim_net_fill_cs_header(&head, seq++, MRIM_CS_MESSAGE, sizeof(uint32_t) + LPSSIZE(to_lps) + LPSSIZE(message_lps) + LPSSIZE(message_rtf_lps));
	mrim_net_send(&head,  sizeof(head));
	mrim_net_send(&flags, sizeof(uint32_t));
	mrim_net_send(to_lps, LPSSIZE(to_lps));
	mrim_net_send(message_lps, LPSSIZE(message_lps));
	mrim_net_send(message_rtf_lps, LPSSIZE(message_rtf_lps));
	ret = mrim_net_send_flush();

	free(to_lps);
	free(message_lps);
	free(message_rtf_lps);

	return ret;
}

/*******************************************************************************
	Send 'ping' packet
*******************************************************************************/
void
mrim_send_ping()
{
	mrim_packet_header_t head;
	
	syslog(LOG_DEBUG, "Send 'PING' packet");

	mrim_net_fill_cs_header(&head, seq++, MRIM_CS_PING, 0);
	mrim_net_send(&head, sizeof(head));
	mrim_net_send_flush();
}

/*******************************************************************************
	Read incoming 'message' packet
*******************************************************************************/
void
mrim_read_message(char *answer, uint32_t len)
{
	uint32_t msg_id;
	uint32_t flags;
	char *from;
//	char *message;
//	char *message_rtf;

	// parse data
	msg_id = *(uint32_t *) answer;
	answer += sizeof(uint32_t);
	flags = *(uint32_t *) answer;
	answer += sizeof(uint32_t);
	from = mrim_net_mksz(answer);
//	answer += LPSSIZE(answer);
//	message = cp1251_to_utf8(mra_net_mksz(answer));
//	message_rtf = mra_net_mksz(answer);

	// send receive ack if needed
	if (!(flags & MESSAGE_FLAG_NORECV)) {
		mrim_net_send_receive_ack(from, msg_id);
	}

	// proceed message
	if (flags & MESSAGE_FLAG_AUTHORIZE) {
		// authorization request
		mrim_net_send_auth_request_ack(from);
//	} else if (flags & MESSAGE_FLAG_SYSTEM) {
//		// system message
//	} else if (flags & MESSAGE_FLAG_CONTACT) {
//		// contacts list
//	} else if (flags & MESSAGE_FLAG_NOTIFY) {
//		// typing notify
//	} else {
//		// casual message
	}

	free(from);
//	free(message);
//	free(message_rtf);
}

/*******************************************************************************
	Read and parce incoming message
*******************************************************************************/
int
mrim_net_read_proceed()
{
	mrim_packet_header_t *head;
	size_t packet_len = 0;
	char *answer;
	char *next_packet;
	char *ddata = NULL;

	if (rx_len == 0) {
		syslog(LOG_DEBUG, "no data");
		return 0;
	}
	if (rx_len < sizeof(mrim_packet_header_t)) {
		syslog(LOG_DEBUG, "need more data");
		return 0;
	}

	// detach MRIM packet header from readed data
	head = (mrim_packet_header_t *) rx_buf;

	// check if we have correct magic
	if (head->magic != CS_MAGIC) {
		syslog(LOG_ERR, "wrong magic: 0x%08x", (uint32_t) head->magic);
		return -1;
	}

	packet_len = sizeof(mrim_packet_header_t) + head->dlen;

	// check if we received full packet
	if (rx_len < packet_len) {
		syslog(LOG_DEBUG, "need more data");
		return 0;
	}

	// get answer value
	answer = rx_buf + sizeof(mrim_packet_header_t);

	// proceed packet
	switch(head->msg) {
		case MRIM_CS_HELLO_ACK:
			// 'hello' packet
			syslog(LOG_DEBUG, "received 'MRIM_CS_HELLO_ACK' packet");
			received_hello_ack = 1;
			break;
		case MRIM_CS_LOGIN_ACK:
			// 'login successful' packet
			syslog(LOG_DEBUG, "received 'MRIM_CS_LOGIN_ACK' packet");
			received_login_ack = 1;
			break;
		case MRIM_CS_LOGIN_REJ:
			// 'login failed' packet
			syslog(LOG_DEBUG, "received 'MRIM_CS_LOGIN_REJ' packet");
			received_login_rej = 1;
			break;
		case MRIM_CS_MESSAGE_ACK:
			// 'receive message' packet
			syslog(LOG_DEBUG, "received 'MRIM_CS_MESSAGE_ACK' packet");
			mrim_read_message(answer, head->dlen);
			break;
		case MRIM_CS_USER_INFO:
			// 'user info' packet
			syslog(LOG_DEBUG, "received 'MRIM_CS_USER_INFO' packet");
			break;
		case MRIM_CS_MESSAGE_STATUS:
			// 'message status' packet
			syslog(LOG_DEBUG, "received 'MRIM_CS_MESSAGE_STATUS' packet");
			break;
		case MRIM_CS_CONTACT_LIST2:
			// 'contact list' packet
			syslog(LOG_DEBUG, "received 'MRIM_CS_CONTACT_LIST2' packet");
			break;
		default:
			// unknown packet
			syslog(LOG_DEBUG, "unknown packet received: 0x%04x", head->msg);
	}

	// if we have more data in incoming buffer
	if (rx_len > packet_len) {
		// cut proceeded packet
		next_packet = rx_buf + packet_len;
		rx_len = rx_len - packet_len;
		memmove(rx_buf, next_packet, rx_len);
		rx_buf = realloc(rx_buf, rx_len);
		return 0;
	} else {
		// else just empty buffer
		rx_len = 0;
		rx_buf = realloc(rx_buf, MRA_BUF_LEN + 1);
	}
	return 1;
}

/*******************************************************************************
	Read data from mail.ru agent server
*******************************************************************************/
int
mrim_net_read()
{
	int len;
	char *buf;

	// increase buffer size
	rx_buf = realloc(rx_buf, rx_len + MRA_BUF_LEN + 1);

	// read data from socket
	buf = rx_buf + rx_len;
	len = read(mra_socket, buf, MRA_BUF_LEN);
	rx_len = rx_len + len;

	if (len < 0 && errno == EAGAIN && errno != EINTR) {
		// read more
		return 0;
	} else if (len < 0) {
		syslog(LOG_ERR, "cannot read data from socket: %s", strerror(errno));
		return -1;
	} else if (len == 0) {
		// server closed the connection
		syslog(LOG_ERR, "server closed the connection: %s", strerror(errno));
		return -1;
	}

	// proceed received data while we can do it =)
	while (mrim_net_read_proceed() == 0);
}

/*******************************************************************************
	Check if data exists
*******************************************************************************/
int
mrim_is_readable(int timeout_sec, int timeout_usec)
{
	struct timeval tv;
	fd_set rset;
	int isready;

	FD_ZERO(&rset);
	FD_SET(mra_socket, &rset);

	tv.tv_sec  = timeout_sec;
	tv.tv_usec = timeout_usec;

again:
	isready = select(mra_socket + 1, &rset, NULL, NULL, &tv);
	if (isready < 0) {
		if (errno == EINTR) goto again;
		syslog(LOG_ERR, "error on select socket: %s", strerror(errno));
		return -1;
	}

	return isready;
}

/*******************************************************************************
	Connect and login
*******************************************************************************/
int
mrim_connect(char *login_host, char *login_port, char *username, char *password)
{
	int i = 0;
	int j = 0;
	int login_data_size = -1;
	char login_data[24];
	char host[16];
	char port[5];

	syslog(LOG_DEBUG, "Start connect to server %s:%s, username: %s, password: %s", login_host, login_port, username, password);

	received_hello_ack = 0;
	received_login_ack = 0;
	received_login_rej = 0;

	if (mra_socket > 0) {
		close(mra_socket);
	}
	
	// let's get server to connect to
	if ((mra_socket = mrim_connect_tcp(login_host, login_port)) == -1) {
		syslog(LOG_ERR, "cannot connect to %s:%s", login_host, login_port);
		return -1;
	}
	if ((login_data_size = read(mra_socket, login_data, sizeof(login_data))) == -1 && errno != EINTR) {
		syslog(LOG_ERR, "cannot read data from socket: %s", strerror(errno));
		return -1;
	}
	if ((mra_socket = close(mra_socket)) == -1 && errno != EINTR) {
		syslog(LOG_ERR, "cannot close socket: %s", strerror(errno));
		return -1;
	}

	for (i = 0; i < login_data_size - 1; i++) {
		if (login_data[i] == ':') {
			host[i] = '\0';
			j = i + 1;
		} else {
			if (j == 0) {
				host[i] = login_data[i];
			} else {
				port[i - j] = login_data[i];
			}
		}
	}
	port[4] = '\0';
	
	syslog(LOG_DEBUG, "Login host: %s", host);
	syslog(LOG_DEBUG, "Login port: %s", port);

	// let's connect to mrim server
	if ((mra_socket = mrim_connect_tcp(host, port)) == -1) {
		syslog(LOG_ERR, "cannot connect to %s:%s", host, port);
		return -1;
	}

	// send 'hello' packet
	if (mrim_send_hello() == -1) {
		syslog(LOG_ERR, "cannot send 'hello' packet");
		return -1;
	}

	// send 'login' packet
	if (mrim_send_auth(username, password, STATUS_ONLINE) == -1) {
		syslog(LOG_ERR, "cannot send 'login' packet");
		return -1;
	}

	if (received_login_rej == 1) {
		syslog(LOG_ERR, "cannot auth: username or password is wrong");
		return -1;
	}
	
	alarm(10);

	return 0;
}

/*******************************************************************************
	Disconnect
*******************************************************************************/
int
mrim_disconnect()
{
	free(rx_buf);
	free(tx_buf);
	if (mra_socket > 0) {
		close(mra_socket);
	}
}

