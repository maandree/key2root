/* See LICENSE file for copyright and license details. */
#include <dirent.h>
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
	fprintf(stderr, "usage: %s [user] ...\n", argv0);
	exit(1);
}


static int
outputkey(char *data, size_t whead, size_t *rheadp, size_t *rhead2p, size_t *linenop, const char *user)
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
		fprintf(stderr, "%s: NUL byte found in /etc/key2root/%s on line %zu\n", argv0, user, *linenop);
		failed = 1;
	}
	if (!memchr(&data[*rheadp], ' ', len)) {
		fprintf(stderr, "%s: no SP byte found in /etc/key2root/%s on line %zu\n", argv0, user, *linenop);
		failed = 1;
	}

	if (!failed) {
		data[*rhead2p] = '\0';
		printf("%s %s\n", user, &data[*rheadp]);
	}

	*rheadp = ++*rhead2p;
	return failed;
}


static int
listkeys(int dir, const char *user)
{
	int fd, failed = 0;
	char *data = NULL, *new;
	size_t size = 0;
	size_t whead = 0;
	size_t rhead = 0;
	size_t rhead2 = 0;
	size_t lineno = 0;
	ssize_t r = 1;

	fd = openat(dir, user, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			return 0;
		fprintf(stderr, "%s: openat /etc/key2root/ %s O_RDONLY: %s\n", argv0, user, strerror(errno));
		return 1;
	}

	while (r) {
		if (whead == size) {
			memmove(data, &data[rhead], whead -= rhead);
			rhead2 -= rhead;
			rhead = 0;
			if (whead == size) {
				new = realloc(data, size += 1024);
				if (!new) {
					fprintf(stderr, "%s: realloc: %s\n", argv0, strerror(errno));
					close(fd);
					return 1;
				}
				data = new;
			}
		}
		r = read(fd, &data[whead], size - whead);
		if (r < 0) {
			fprintf(stderr, "%s: read /etc/key2root/%s: %s\n", argv0, user, strerror(errno));
			close(fd);
			return 1;
		}
		whead += (size_t)r;

		while (rhead2 < whead)
			failed |= outputkey(data, whead, &rhead, &rhead2, &lineno, user);
	}

	if (rhead != whead) {
		fprintf(stderr, "%s: file truncated: /etc/key2root/%s\n", argv0, user);
		failed = 1;
	}

	close(fd);
	return failed;
}


int
main(int argc, char *argv[])
{
	int failed = 0, fd;
	DIR *dir;
	struct dirent *f;

	ARGBEGIN {
	default:
		usage();
	} ARGEND;

	if (argc) {
		fd = open("/etc/key2root/", O_PATH);
		if (fd < 0) {
			if (errno == ENOENT)
				return 0;
			fprintf(stderr, "%s: open /etc/key2root/ O_PATH: %s\n", argv0, strerror(errno));
			exit(1);
		}
		for (; *argv; argv++) {
			if (!(*argv)[0] || (*argv)[0] == '.' || strchr(*argv, '/') || strchr(*argv, '~')) {
				fprintf(stderr, "%s: bad user name specified: %s\n", argv0, *argv);
				failed = 1;
			} else {
				failed |= listkeys(fd, *argv);
			}
		}
		close(fd);
	} else {
		dir = opendir("/etc/key2root/");
		if (!dir) {
			if (errno == ENOENT)
				return 0;
			fprintf(stderr, "%s: opendir /etc/key2root/: %s\n", argv0, strerror(errno));
			exit(1);
		}
		fd = dirfd(dir);
		if (fd < 0)
			abort();
		while ((errno = 0, f = readdir(dir))) {
			if (f->d_name[0] == '.' || strchr(f->d_name, '~'))
				continue;
			listkeys(fd, f->d_name);
		}
		if (errno || closedir(dir)) {
			fprintf(stderr, "%s: readdir /etc/key2root/: %s\n", argv0, strerror(errno));
			exit(1);
		}
	}

	if (fflush(stdout) || ferror(stdout) || fclose(stdout)) {
		fprintf(stderr, "%s: print: %s\n", argv0, strerror(errno));
		exit(1);
	}
	return failed;
}
