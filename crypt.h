/* See LICENSE file for copyright and license details. */
#include <stddef.h>
#include <libar2.h>

char *key2root_crypt(char *msg, size_t msglen, const char *paramstr, int autoerase);


#define explicit_bzero key2root_erase
static inline void
key2root_erase(void *msg, size_t msglen)
{
	libar2_erase(msg, msglen);
}
