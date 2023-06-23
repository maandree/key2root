/* See LICENSE file for copyright and license details. */
#include "crypt.h"
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libar2simplified.h>
#include <libar2.h>

extern char *argv0;


char *
key2root_crypt(char *msg, size_t msglen, const char *paramstr, int autoerase)
{
	struct libar2_argon2_parameters *params = NULL;
	char *end, *ret = NULL, *hash = NULL;
	size_t size;
	struct libar2_context ctx;

	libar2simplified_init_context(&ctx);
	ctx.autoerase_message = (unsigned char)autoerase;

	if (!paramstr)
		paramstr = libar2simplified_recommendation(0);

	params = libar2simplified_decode_r(paramstr, NULL, &end, NULL, NULL);
	if (!params) {
		fprintf(stderr, "%s: libar2simplified_decode_r %s: %s\n", argv0, paramstr, strerror(errno));
		return NULL;
	}
	if (*end) {
		fprintf(stderr, "%s: libar2simplified_decode_r %s: excess data at end parameter string: %s\n", argv0, paramstr, end);
		goto out;
	}

	size = libar2_hash_buf_size(params);
	if (!size)
		abort();
	if (!size || !(hash = malloc(size))) {
		fprintf(stderr, "%s: malloc %zu: %s\n", argv0, size, strerror(errno));
		goto out;
	}

	if (libar2_hash(hash, msg, msglen, params, &ctx)) {
		if (autoerase)
			libar2_erase(msg, msglen);
		fprintf(stderr, "%s: libar2simplified_hash %s: %s\n", argv0, paramstr, strerror(errno));
		goto out;
	}

	ret = libar2simplified_encode(params, hash);

out:
	if (params) {
		libar2_erase(params->salt, params->saltlen);
		free(params);
	}
	free(hash);
	return ret;
}
