/* See LICENSE file for copyright and license details. */
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "arg.h"


#define EXIT_AUTH   124
#define EXIT_ERROR  125
#define EXIT_EXEC   126
#define EXIT_NOENT  127


char *argv0;

/* Keep list in sync with asroot(8)'s list */
static const char *env_whitelist[] = {
	"DISPLAY=",
	"WAYLAND_DISPLAY=",
	"PATH=",
	"TERM=",
	"COLORTERM=",
	"XAUTHORITY=",
	"LANG=",
	"LANGUAGE=",
	"LOCALE=",
	"LC_CTYPE=",
	"LC_NUMERIC=",
	"LC_TIME=",
	"LC_COLLATE=",
	"LC_MONETARY=",
	"LC_MESSAGES=",
	"LC_PAPER=",
	"LC_NAME=",
	"LC_ADDRESS=",
	"LC_TELEPHONE=",
	"LC_MEASUREMENT=",
	"LC_IDENTIFICATION=",
	"LC_ALL=",
	"LOCPATH=",
	"NLSPATH=",
	"TZ=",
	"TZDIR=",
	"SDL_VIDEO_FULLSCREEN_DISPLAY=",
	"EDITOR=",
	"VISUAL=",
	"BROWSER=",
	"DESKTOP_SESSION=",
	"LS_COLORS=",
	"GTK_THEME=",
	"QT_STYLE_OVERRIDE=",
	"PWD=",
	"OLDPWD=",
	"JAVA_HOME=",
	"_JAVA_AWT_WM_NONREPARENTING=",
	"_JAVA_OPTIONS=",
	"MAIN_ALSA_MIXER=",
	"MAIN_ALSA_CARD=",
	"XDG_SEAT=",
	"XDG_SESSION_TYPE=",
	"XDG_SESSION_CLASS=",
	"XDG_VTNR=",
	"XDG_SESSION_ID=",
	"XDG_DATA_DIRS=",
	"XDG_CONFIG_DIRS=",
	"MANPATH=",
	"INFODIR=",
	"PAGER=",
	"ftp_proxy=",
	"http_proxy=",
	NULL
};


static void
usage(void)
{
	fprintf(stderr, "usage: %s [-k key-name] [-e] command [argument] ...\n", argv0);
	exit(EXIT_ERROR);
}


static int
forward(char *data, size_t len)
{
	int fds[2];
	size_t off;
	ssize_t r;

	/* We are using sockets because they cannot be hijacked via /proc/<pid>/fd/ */

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, fds)) {
		fprintf(stderr, "%s: socketpair PF_LOCAL SOCK_STREAM 0: %s\n", argv0, strerror(errno));
		return -1;
	}
	if (shutdown(fds[0], SHUT_WR)) {
		fprintf(stderr, "%s: shutdown <socket> SHUT_WR: %s\n", argv0, strerror(errno));
		close(fds[0]);
		close(fds[1]);
		return -1;
	}
	if (shutdown(fds[1], SHUT_RD)) {
		fprintf(stderr, "%s: shutdown <socket> SHUT_RD: %s\n", argv0, strerror(errno));
		close(fds[0]);
		close(fds[1]);
		return -1;
	}

	switch (fork()) {
	case -1:
		fprintf(stderr, "%s: fork: %s\n", argv0, strerror(errno));
		close(fds[0]);
		close(fds[1]);
		return -1;
	case 0:
		close(fds[0]);
		break;
	default:
		close(fds[1]);
		return fds[0];
	}

	for (off = 0; off < len; off += (size_t)r) {
		r = write(fds[1], &data[off], len - off);
		if (r < 0) {
			fprintf(stderr, "%s: write <socket>: %s\n", argv0, strerror(errno));
			close(fds[1]);
			_exit(1);
		}
		explicit_bzero(&data[off], (size_t)r);
	}

	close(fds[1]);
	_exit(0);
}


static char **
set_environ(void)
{
	char **new_environ;
	size_t i, j, n, len;
	struct passwd *pw;

	new_environ = calloc(sizeof(env_whitelist) / sizeof(*env_whitelist) + 5, sizeof(*env_whitelist));
	if (!new_environ) {
		fprintf(stderr, "%s: calloc %zu %zu: %s\n",
			argv0, sizeof(env_whitelist) / sizeof(*env_whitelist) + 5, sizeof(*env_whitelist), strerror(errno));
		exit(EXIT_ERROR);
	}
	for (i = 0, n = 0; env_whitelist[i]; i++) {
		len = strlen(env_whitelist[i]);
		for (j = 0; environ[j]; j++) {
			if (!strncmp(environ[j], env_whitelist[i], len)) {
				new_environ[n++] = environ[j];
				break;
			}
		}
	}

	errno = 0;
	pw = getpwuid(0);
	if (!pw) {
		if (errno)
			fprintf(stderr, "%s: getpwuid 0: %s\n", argv0, strerror(errno));
		else
			fprintf(stderr, "%s: cannot find root user\n", argv0);
		exit(EXIT_ERROR);
	}

	if (pw->pw_dir && *pw->pw_dir) {
		len = strlen(pw->pw_dir);
		len += sizeof("HOME=");
		new_environ[n] = malloc(len);
		if (!new_environ[n])
			fprintf(stderr, "%s: malloc %zu: %s\n", argv0, len, strerror(errno));
		stpcpy(stpcpy(new_environ[n++], "HOME="), pw->pw_dir);
	}
	if (pw->pw_name && *pw->pw_name) {
		len = strlen(pw->pw_name);
		len += sizeof("LOGNAME=");
		new_environ[n] = malloc(len);
		if (!new_environ[n])
			fprintf(stderr, "%s: malloc %zu: %s\n", argv0, len, strerror(errno));
		stpcpy(stpcpy(new_environ[n++], "LOGNAME="), pw->pw_name);

		len -= sizeof("LOGNAME=");
		len += sizeof("USER=");
		new_environ[n] = malloc(len);
		if (!new_environ[n])
			fprintf(stderr, "%s: malloc %zu: %s\n", argv0, len, strerror(errno));
		stpcpy(stpcpy(new_environ[n++], "USER="), pw->pw_name);

		len -= sizeof("USER=");
		len += sizeof("MAIL=/var/spool/mail/");
		new_environ[n] = malloc(len);
		if (!new_environ[n])
			fprintf(stderr, "%s: malloc %zu: %s\n", argv0, len, strerror(errno));
		stpcpy(stpcpy(new_environ[n++], "MAIL=/var/spool/mail/"), pw->pw_name);
	}
	if (pw->pw_shell && *pw->pw_shell) {
		len = strlen(pw->pw_shell);
		len += sizeof("SHELL=");
		new_environ[n] = malloc(len);
		if (!new_environ[n])
			fprintf(stderr, "%s: malloc %zu: %s\n", argv0, len, strerror(errno));
		stpcpy(stpcpy(new_environ[n++], "SHELL="), pw->pw_shell);
	}
	new_environ[n] = NULL;

	return new_environ;
}


int
main(int argc, char *argv[])
{
	int keep_env = 0;
	char **new_environ = NULL;
	const char *key_name = NULL;
	char *key = NULL, *key_new;
	size_t key_len = 0;
	size_t key_size = 0;
	ssize_t r;
	int fd;

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

	if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
		fprintf(stderr, "%s: mlockall MCL_CURRENT|MCL_FUTURE: %s\n", argv0, strerror(errno));
		exit(EXIT_ERROR);
	}

	for (;;) {
		if (key_len == key_size) {
			key_new = malloc(key_size += 1024);
			if (!key_new) {
				explicit_bzero(key, key_len);
				fprintf(stderr, "%s: malloc: %s\n", argv0, strerror(errno));
				exit(EXIT_ERROR);
			}
			memcpy(key_new, key, key_len);
			explicit_bzero(key, key_len);
			free(key);
			key = key_new;
		}
		r = read(STDIN_FILENO, &key[key_len], key_size - key_len);
		if (r <= 0) {
			if (!r)
				break;
			explicit_bzero(key, key_len);
			fprintf(stderr, "%s: read <stdin>: %s\n", argv0, strerror(errno));
			exit(EXIT_ERROR);
		}
		key_len += (size_t)r;
	}

	/* TODO authenticate */

	fd = forward(key, key_len);
	if (fd < 0) {
		explicit_bzero(key, key_len);
		exit(EXIT_ERROR);
	}

	explicit_bzero(key, key_len);

	if (!keep_env)
		new_environ = set_environ();

	if (setgid(0)) {
		fprintf(stderr, "%s: setgid 0: %s\n", argv0, strerror(errno));
		exit(EXIT_ERROR);
	}
	if (setuid(0)) {
		fprintf(stderr, "%s: setuid 0: %s\n", argv0, strerror(errno));
		exit(EXIT_ERROR);
	}

	if (fd != STDIN_FILENO) {
		if (dup2(fd, STDIN_FILENO) != STDIN_FILENO) {
			fprintf(stderr, "%s: dup2 <socket> <stdin>: %s\n", argv0, strerror(errno));
			exit(EXIT_ERROR);
		}
		close(fd);
	}

	if (new_environ)
		environ = new_environ;
	execvp(argv[0], argv);
	fprintf(stderr, "%s: execvpe %s: %s\n", argv0, argv[0], strerror(errno));
	return errno == ENOENT ? EXIT_NOENT : EXIT_EXEC;
}
