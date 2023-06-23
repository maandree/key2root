/* See LICENSE file for copyright and license details. */
#include <stdio.h>
#include <stdlib.h>

#include "arg.h"


char *argv0;


static void
usage(void)
{
	fprintf(stderr, "usage: %s [user] ...\n", argv0);
	exit(1);
}


int
main(int argc, char *argv[])
{
	ARGBEGIN {
	default:
		usage();
	} ARGEND;

	return 0;
}
