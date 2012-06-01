#include "mrad.h"

/*******************************************************************************
	Usage
*******************************************************************************/
void
print_usage(int argc, char *argv[])
{
	if (argc >= 1) {
		printf("Usage: %s [options]\n", argv[0]);
		printf("Options:\n");
		printf("  -u  Mail.Ru Agent username.\n");
		printf("  -p  Mail.Ru Agent password.\n");
		printf("  -l  Port to listen to.\n");
		printf("  -n  Don't fork off as a daemon.\n");
		printf("  -h  Show this help screen.\n");
		printf("\n");
	}
}

/*******************************************************************************
	Signal handler
*******************************************************************************/
void
signal_handler(int sig)
{
	switch(sig) {
		case SIGALRM:
			if(mrim_send_ping() != -1){
				alarm(10);
			}
			break;
		case SIGINT:
			need_exit = 1;
			break;
		case SIGHUP:
			syslog(LOG_WARNING, "Received SIGHUP signal");
			break;
		case SIGTERM:
			syslog(LOG_WARNING, "Received SIGTERM signal");
			break;
		default:
			syslog(LOG_WARNING, "Unhandled signal (%d) %s", strsignal(sig));
			break;
	}
}

/*******************************************************************************
	Main
*******************************************************************************/
int
main(int argc, char *argv[])
{
#if defined(DEBUG)
	int daemonize = 0;
#else
	int daemonize = 1;
#endif
	char *username = NULL;
	char *password = NULL;
	int  port     = LISTEN_PORT;

	// Setup signal handling before we start
	signal(SIGALRM, signal_handler);
	signal(SIGINT,  signal_handler);
	signal(SIGHUP,  signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGQUIT, signal_handler);

	int c;
	while((c = getopt(argc, argv, "u:p:l:nh|help")) != -1) {
		switch(c){
			case 'h':
				print_usage(argc, argv);
				exit(0);
				break;
			case 'n':
				daemonize = 0;
				break;
			case 'u':
				username = optarg;
				break;
			case 'p':
				password = optarg;
				break;
			case 'l':
				port = atoi(optarg);
			case '?':
				if (optopt == 'u' || optopt == 'p' || optopt == 'l')
					syslog(LOG_ERR, "Option -%c requires an argument.\n", optopt);
				else if (isprint (optopt))
					syslog(LOG_ERR, "Unknown option `-%c'.\n", optopt);
				else
					syslog(LOG_ERR, "Unknown option character `\\x%x'.\n", optopt);
				break;
			default:
				print_usage(argc, argv);
				exit(0);
				break;
		}
	}

	if (username == NULL || password == NULL) {
		syslog(LOG_ERR, "No username or password defined");
		print_usage(argc, argv);
		exit(EXIT_FAILURE);
	}

	syslog(LOG_INFO, "%s daemon starting up", DAEMON_NAME);

	// Setup syslog logging - see SETLOGMASK(3)
#if defined(DEBUG)
	setlogmask(LOG_UPTO(LOG_DEBUG));
	openlog(DAEMON_NAME, LOG_CONS | LOG_NDELAY | LOG_PERROR | LOG_PID, LOG_USER);
#else
	setlogmask(LOG_UPTO(LOG_INFO));
	openlog(DAEMON_NAME, LOG_CONS, LOG_USER);
#endif

	// Our process ID and Session ID
	pid_t pid, sid;

	if (daemonize) {
		syslog(LOG_INFO, "starting the daemonizing process");

		// Fork off the parent process
		pid = fork();
		if (pid < 0) {
			exit(EXIT_FAILURE);
		}
		// If we got a good PID, then we can exit the parent process
		if (pid > 0) {
			exit(EXIT_SUCCESS);
		}

		// Change the file mode mask
		umask(0);

		// Create a new SID for the child process
		sid = setsid();
		if (sid < 0) {
			exit(EXIT_FAILURE);
		}

		// Change the current working directory
		if ((chdir("/")) < 0) {
			exit(EXIT_FAILURE);
		}

		// Close out the standard file descriptors
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}
			
	if (socket_open(port) == -1) {
		syslog(LOG_ERR, "Can't open socket to listen incoming messages on");
		exit(EXIT_FAILURE);
	}

	// Main cycle
	syslog(LOG_INFO, "%s running", DAEMON_NAME);
	while(1) {
		// Connect to mail.ru agent if not connected yet
		if (mrim_connected == 0) {
			if (mrim_connect(MRA_HOST, MRA_PORT, username, password) == -1) {
				syslog(LOG_ERR, "Can't connect to mail.ru agent");
				sleep(5);
				continue;
			}
			mrim_connected = 1;
		}

		// read data from local socket if needed
		if (socket_is_readable(0, 500)) {
			socket_read();
		}

		// read data from MRIM if needed
		if (mrim_is_readable(0, 100)) {
			if(mrim_net_read() == -1){
				mrim_connected = 0;
			}
		}

		// exit on Ctrl+C
		if (need_exit) {
			break;
		}
	}

	mrim_disconnect();
	socket_close();

	syslog(LOG_INFO, "%s daemon exiting", DAEMON_NAME);

	exit(EXIT_SUCCESS);
}

