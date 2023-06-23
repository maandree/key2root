/* See LICENSE file for copyright and license details. */
#include <stdio.h>
#include <stdlib.h>

#include "arg.h"


char *argv0;


static void
usage(void)
{
	fprintf(stderr, "usage: %s user key-name ...\n", argv0);
	exit(1);
}


int
main(int argc, char *argv[])
{
	const char *user;
	int i, failed = 0;

	ARGBEGIN {
	default:
		usage();
	} ARGEND;

	if (argc < 2)
		usage();

	user = *argv++;
	argc--;

	if (!user[0] || user[0] == '.' || strchr(user, '/') || strchr(user, '~')) {
		fprintf(stderr, "%s: bad user name specified: %s\n", argv0, user);
		failed = 1;
	}
	for (i = 0; i < argc; i++) {
		if (argv[i][strcspn(argv[i], " \t\f\n\r\v")]) {
			fprintf(stderr, "%s: bad key name specified: %s, includes whitespace\n", argv0, argv[i]);
			failed = 1;
		}
	}
	if (failed)
		return 1;

	/* TODO */

	return 0;
}
