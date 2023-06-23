/* See LICENSE file for copyright and license details. */
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "arg.h"


char *argv0;


static void
usage(void)
{
	fprintf(stderr, "usage: %s [-r] user key-name [crypt-parameters]\n", argv0);
	exit(1);
}


int
main(int argc, char *argv[])
{
	const char *user;
	const char *keyname;
	const char *parameters;
	int allow_replace = 0;
	int failed = 0;

	ARGBEGIN {
	case 'r':
		allow_replace = 1;
		break;
	default:
		usage();
	} ARGEND;

	if (argc < 2 || argc > 3)
		usage();

	user = argv[0];
	keyname = argv[1];
	parameters = argv[2];

	if (!user[0] || user[0] == '.' || strchr(user, '/') || strchr(user, '~')) {
		fprintf(stderr, "%s: bad user name specified: %s\n", argv0, user);
		failed = 1;
	}
	if (keyname[strcspn(keyname, " \t\f\n\r\v")]) {
		fprintf(stderr, "%s: bad key name specified: %s, includes whitespace\n", argv0, keyname);
		failed = 1;
	}
	if (isatty(STDIN_FILENO)) {
		fprintf(stderr, "%s: standard input must not be a TTY.\n", argv0);
		failed = 1;
	}
	if (failed)
		return 1;

	if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
		fprintf(stderr, "%s: mlockall MCL_CURRENT|MCL_FUTURE: %s\n", argv0, strerror(errno));
		exit(1);
	}

	/* TODO hash input */
	/* TODO add or replace key */
	/* TODO save changes, mode shall be 0600 */

	return 0;
}
