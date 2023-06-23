/* See LICENSE file for copyright and license details. */
#include <stdio.h>
#include <stdlib.h>
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
	int allow_replace = 0;

	ARGBEGIN {
	case 'r':
		allow_replace = 1;
		break;
	default:
		usage();
	} ARGEND;

	if (argc < 2 || argc > 3)
		usage();

	if (isatty(STDIN_FILENO)) {
		fprintf(stderr, "%s: standard input must not be a TTY.\n", argv0);
		exit(1);
	}

	return 0;
}
