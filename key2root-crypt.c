/* See LICENSE file for copyright and license details. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "arg.h"
#include "crypt.h"


char *argv0;


static void
usage(void)
{
	fprintf(stderr, "usage: %s [crypt-parameters]\n", argv0);
	exit(1);
}


int
main(int argc, char *argv[])
{
	const char *parameters;
	char *key = NULL, *new;
	size_t key_len = 0;
	size_t key_size = 0;
	char *hash;
	ssize_t r;

	ARGBEGIN {
	default:
		usage();
	} ARGEND;

	if (argc > 1)
		usage();

	parameters = argv[0];

	for (;;) {
		if (key_len == key_size) {
			new = malloc(1 + (key_size += 1024));
			if (!new) {
				explicit_bzero(key, key_len);
				fprintf(stderr, "%s: read <stdin>: %s\n", argv0, strerror(errno));
				exit(1);
			}
			memcpy(new, key, key_len);
			explicit_bzero(key, key_len);
			free(key);
			key = new;
		}
		r = read(STDIN_FILENO, &key[key_len], key_size - key_len);
		if (r <= 0) {
			if (!r)
				break;
			explicit_bzero(key, key_len);
			fprintf(stderr, "%s: read <stdin>: %s\n", argv0, strerror(errno));
			exit(1);
		}
		key_len += (size_t)r;
	}
	hash = key2root_crypt(key, key_len, parameters, 1);
	if (!hash)
		exit(1);
	free(key);
	printf("%s\n", hash);
	free(hash);

	if (fflush(stdout) || ferror(stdout) || fclose(stdout)) {
		fprintf(stderr, "%s: printf: %s\n", argv0, strerror(errno));
		exit(1);
	}
	return 0;
}
