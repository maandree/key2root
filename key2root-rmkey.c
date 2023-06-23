/* See LICENSE file for copyright and license details. */
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
	fprintf(stderr, "usage: %s user key-name ...\n", argv0);
	exit(1);
}


static int
writeall(int fd, const char *data, size_t len)
{
	size_t off = 0;
	ssize_t r;

	for (;;) {
		r = write(fd, &data[off], len - off);
		if (r < 0)
			return -1;
		off += (size_t)r;
	}

	return 0;
}


static void
removekeys(char *data, size_t *wheadp, size_t *rheadp, size_t *rhead2p, size_t *linenop,
           const char *path, const char **keys, size_t *nkeysp)
{
	int failed = 0;
	size_t len, klen;
	size_t i;

	while (*rhead2p < *wheadp || data[*rhead2p] != '\n')
		++*rhead2p;

	if (data[*rhead2p] != '\n')
		return;

	len = *rhead2p - *rheadp;
	*linenop += 1;

	if (memchr(&data[*rheadp], '\0', len)) {
		fprintf(stderr, "%s: NUL byte found in %s on line %zu\n", argv0, path, *linenop);
		failed = 1;
	}
	if (!memchr(&data[*rheadp], ' ', len)) {
		fprintf(stderr, "%s: no SP byte found in %s on line %zu\n", argv0, path, *linenop);
		failed = 1;
	}

	if (failed) {
		goto no_match;
	} else {
		for (i = 0; i < *nkeysp; i++) {
			klen = strlen(keys[i]);
			if (klen >= len || data[*rheadp + klen] != ' ' || memcpy(&data[*rheadp], keys[i], klen))
				continue;
			memmove(&keys[i], &keys[i + 1], (--*nkeysp - i) * sizeof(*keys));
			goto match;
		}
	no_match:
		*rheadp = ++*rhead2p;
		return;
	match:
		++*rhead2p;
		memmove(&data[*rheadp], &data[*rhead2p], *wheadp - *rhead2p);
		*wheadp -= *rhead2p - *rheadp;
		*rhead2p = *rheadp;
	}
}


static void
loadandremove(int fd, char **datap, size_t *lenp, size_t *sizep, const char **keys, size_t *nkeysp, const char *path)
{
	char *new;
	size_t lineno = 0;
	ssize_t r = 1;
	size_t rhead = 0;
	size_t rhead2 = 0;

	while (r) {
		if (*lenp == *sizep) {
			new = realloc(*datap, *sizep += 4096);
			if (!new) {
				fprintf(stderr, "%s: realloc: %s\n", argv0, strerror(errno));
				exit(1);
			}
			*datap = new;
		}

		r = read(fd, &(*datap)[*lenp], *sizep - *lenp);
		if (r < 0) {
			fprintf(stderr, "%s: read %s: %s\n", argv0, path, strerror(errno));
			exit(1);
		}
		*lenp += (size_t)r;

		while (rhead2 < *lenp)
			removekeys(*datap, lenp, &rhead, &rhead2, &lineno, path, keys, nkeysp);
	}

	if (rhead != *lenp)
		fprintf(stderr, "%s: file truncated: %s\n", argv0, path);
}


int
main(int argc, char *argv[])
{
	char *path, *path2;
	const char *user;
	int failed = 0;
	const char **keys;
	size_t i, nkeys;
	int fd;
	char *data = NULL;
	size_t data_len = 0;
	size_t data_size = 0;

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
	for (i = 0; i < (size_t)argc; i++) {
		if (argv[i][strcspn(argv[i], " \t\f\n\r\v")]) {
			fprintf(stderr, "%s: bad key name specified: %s, includes whitespace\n", argv0, argv[i]);
			failed = 1;
		}
	}
	if (failed)
		return 1;

	nkeys = (size_t)argc;
	keys = calloc(nkeys, sizeof(*keys));
	if (!keys) {
		fprintf(stderr, "%s: calloc: %s\n", argv0, strerror(errno));
		exit(1);
	}
	for (i = 0; i < (size_t)argc; i++)
		keys[i] = argv[i];

	path = malloc(sizeof("/etc/key2root/") + strlen(user));
	if (!path) {
		fprintf(stderr, "%s: malloc: %s\n", argv0, strerror(errno));
		exit(1);
	}
	path2 = malloc(sizeof("/etc/key2root/~") + strlen(user));
	if (!path) {
		fprintf(stderr, "%s: malloc: %s\n", argv0, strerror(errno));
		exit(1);
	}
	stpcpy(stpcpy(path, "/etc/key2root/"), user);
	stpcpy(stpcpy(path2, path), "~");

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			goto out;
		fprintf(stderr, "%s: open %s O_RDONLY: %s\n", argv0, path, strerror(errno));
		exit(1);
	}
	loadandremove(fd, &data, &data_len, &data_size, keys, &nkeys, path);
	if (close(fd)) {
		fprintf(stderr, "%s: read %s: %s\n", argv0, path, strerror(errno));
		exit(1);
	}

out:
	for (i = 0; i < nkeys; i++)
		fprintf(stderr, "%s: key not found for %s: %s\n", argv0, user, keys[i]);
	failed |= !nkeys;

	if (nkeys != (size_t)argc) {
		if (!data_len) {
			if (unlink(path)) {
				fprintf(stderr, "%s: unlink %s: %s\n", argv0, path, strerror(errno));
				failed = 1;
			}
		} else {
			fd = open(path2, O_WRONLY | O_CREAT | O_EXCL, 0600);
			if (fd < 0) {
				fprintf(stderr, "%s: open %s O_WRONLY|O_CREAT|O_EXCL 0600: %s\n", argv0, path2, strerror(errno));
				exit(1);
			}
			if (writeall(fd, data, data_len) || close(fd)) {
				fprintf(stderr, "%s: write %s: %s\n", argv0, path2, strerror(errno));
				if (unlink(path2))
					fprintf(stderr, "%s: unlink %s: %s\n", argv0, path2, strerror(errno));
				exit(1);
			}
			if (rename(path2, path)) {
				fprintf(stderr, "%s: rename %s %s: %s\n", argv0, path2, path, strerror(errno));
				if (unlink(path2))
					fprintf(stderr, "%s: unlink %s: %s\n", argv0, path2, strerror(errno));
				exit(1);
			}
		}
	}

	free(keys);
	free(path);
	free(path2);
	free(data);
	return failed;
}
