.POSIX:

## DO NOT MODIFY THIS FILE

PEPPER_VALIDATION_INPUT  = $$argon2id$$v=19$$m=3072,t=32,p=4$$ABCDabcd1234$$*16
PEPPER_VALIDATION_OUTPUT = $$argon2id$$v=19$$m=3072,t=32,p=4$$ABCDabcd1234$$NVf6KJj9PDPW8BYdduqPWA

check:
	+@test -x key2root-crypt || $(MAKE) key2root-crypt
	test "$$(printf '' | ./key2root-crypt '$(PEPPER_VALIDATION_INPUT)')" = '$(PEPPER_VALIDATION_OUTPUT)'
