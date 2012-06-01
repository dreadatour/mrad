#ifndef __MRAD_H
#define __MRAD_H

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

#define DAEMON_NAME "mrad"
#define PID_FILE    "/var/run/mrad.pid"

#define MRA_HOST    "mrim.mail.ru"
#define MRA_PORT    "2042"

#define LISTEN_PORT 20202


#endif
