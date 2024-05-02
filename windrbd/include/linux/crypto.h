#ifndef _LINUX_CRYPTO_H
#define _LINUX_CRYPTO_H

#define CRYPTO_MAX_ALG_NAME (64)

struct crypto_tfm {
	int nothing;
};

extern void *crypto_alloc_tfm(char *name, u32 mask);
extern unsigned int crypto_tfm_alg_digestsize(struct crypto_tfm *tfm);

#endif
