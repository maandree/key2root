/* See LICENSE file for copyright and license details. */
#include <stdio.h>
#include <stdlib.h>

#include "arg.h"


char *argv0;


static void
usage(void)
{
	fprintf(stderr, "usage: %s [-k key-name] [-e] command [argument] ...\n", argv0);
	exit(125);
}


int
main(int argc, char *argv[])
{
	int keep_env = 0;
	const char *key_name = NULL;

	ARGBEGIN {
	case 'e':
		keep_env = 1;
		break;
	case 'k':
		if (key_name)
			usage();
		key_name = EARGF(usage());
		break;
	default:
		usage();
	} ARGEND;

	if (!argc)
		usage();

	return 0;
}
