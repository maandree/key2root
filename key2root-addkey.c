/* See LICENSE file for copyright and license details. */
#include <sys/mman.h>
#include <sys/stat.h>
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


static int
writeall(int fd, const char *data, size_t len)
{
	size_t off = 0;
	ssize_t r;

	while (off < len) {
		r = write(fd, &data[off], len - off);
		if (r < 0)
			return -1;
		off += (size_t)r;
	}

	return 0;
}


static int
checkkey(char *data, size_t whead, size_t *rheadp, size_t *rhead2p, size_t *linenop,
         const char *keyname, size_t klen, const char *path)
{
	int failed = 0;
	size_t len;

	while (*rhead2p < whead || data[*rhead2p] != '\n')
		++*rhead2p;

	if (data[*rhead2p] != '\n')
		return 0;

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

	if (failed || klen >= len || data[*rheadp + klen] != ' ' || memcpy(&data[*rheadp], keyname, klen)) {
		*rheadp = ++*rhead2p;
		return 0;
	} else {
		++*rhead2p;
		return 1;
	}
}


static void
loadandlocate(size_t *beginning_out, size_t *end_out, int fd, char **datap, size_t *lenp, size_t *sizep,
              const char *keyname, const char *path)
{
	size_t klen = strlen(keyname);
	char *new;
	size_t rhead = 0;
	size_t rhead2 = 0;
	size_t lineno = 0;
	ssize_t r = 1;

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

		while (rhead2 < *lenp) {
			if (!checkkey(*datap, *lenp, &rhead, &rhead2, &lineno, keyname, klen, path))
				continue;
			*beginning_out = rhead;
			*end_out = rhead = rhead2;
		}
	}

	if (rhead != *lenp) {
		fprintf(stderr, "%s: file truncated: %s\n", argv0, path);
		if (memchr(&(*datap)[rhead], '\0', *lenp - rhead))
			fprintf(stderr, "%s: NUL byte found in %s on line %zu\n", argv0, path, lineno + 1);
	}
}


int
main(int argc, char *argv[])
{
	const char *user;
	const char *keyname;
	const char *parameters;
	char *path, *path2;
	char *data = NULL;
	size_t data_len = 0;
	size_t data_size = 0;
	size_t beginning = 0;
	size_t end = 0;
	int allow_replace = 0;
	int failed = 0;
	int fd;

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

	path = malloc(sizeof(KEYPATH"/") + strlen(user));
	if (!path) {
		fprintf(stderr, "%s: malloc: %s\n", argv0, strerror(errno));
		exit(1);
	}
	path2 = malloc(sizeof(KEYPATH"/~") + strlen(user));
	if (!path) {
		fprintf(stderr, "%s: malloc: %s\n", argv0, strerror(errno));
		exit(1);
	}
	stpcpy(stpcpy(path, KEYPATH"/"), user);
	stpcpy(stpcpy(path2, path), "~");

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (errno != ENOENT) {
			fprintf(stderr, "%s: open %s O_RDONLY: %s\n", argv0, path, strerror(errno));
			exit(1);
		}
		beginning = end = 0;
	} else {
		loadandlocate(&beginning, &end, fd, &data, &data_len, &data_size, keyname, path);
		if (close(fd)) {
			fprintf(stderr, "%s: read %s: %s\n", argv0, path, strerror(errno));
			exit(1);
		}
		if (beginning == end)
			beginning = end = 0; /* make sure the new key is not concatenated onto a truncated line at the end */
	}
	if (!allow_replace && beginning != end) {
		fprintf(stderr, "%s: key already exists: %s\n", argv0, keyname);
		exit(1);
	}
	/* TODO add or replace key */

	if (mkdir(KEYPATH, 0700) && errno != EEXIST) {
		fprintf(stderr, "%s: mkdir %s: %s\n", argv0, KEYPATH, strerror(errno));
		exit(1);
	}
	fd = open(path2, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		fprintf(stderr, "%s: open %s O_WRONLY|O_CREAT|O_EXCL 0600: %s\n", argv0, path2, strerror(errno));
		exit(1);
	}
	if (writeall(fd, data, data_len)) {
		fprintf(stderr, "%s: write %s: %s\n", argv0, path2, strerror(errno));
		close(fd);
		goto saved_failed;
	}
	if (close(fd)) {
		fprintf(stderr, "%s: write %s: %s\n", argv0, path2, strerror(errno));
		goto saved_failed;
	}
	if (rename(path2, path)) {
		fprintf(stderr, "%s: rename %s %s: %s\n", argv0, path2, path, strerror(errno));
	saved_failed:
		if (unlink(path2))
			fprintf(stderr, "%s: unlink %s: %s\n", argv0, path2, strerror(errno));
		exit(1);
	}

	free(path);
	free(path2);
	free(data);
	return 0;
}
