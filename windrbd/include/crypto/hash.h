#ifndef _CRYPTO_HASH_H
#define _CRYPTO_HASH_H

#include <drbd_windows.h>
#include <ntddk.h>

/* We only support crc32c */

#define CRYPTO_ALG_ASYNC 4711
#define CRYPTO_ALG_TYPE_HASH CRYPTO_ALG_TYPE_DIGEST

#define CRYPTO_TFM_NEED_KEY		0x00000001

struct crypto_shash {
	const uint8_t *key;
	int keylen;
};

struct shash_desc {
	uint32_t crc;
	struct crypto_shash *tfm;
};

#define SHASH_DESC_ON_STACK(shash, ctx)				  \
	char __##shash##_desc[sizeof(struct shash_desc)];	  \
	struct shash_desc *shash = (struct shash_desc *)__##shash##_desc

static inline struct crypto_shash *
crypto_alloc_shash(const char *alg_name, u32 type, u32 mask)
{
	struct crypto_shash *ch;

	if (strcmp(alg_name, "crc32c") != 0)
		return ERR_PTR(-EOPNOTSUPP);

	ch = kmalloc(sizeof(*ch), GFP_KERNEL, 'HSWD');
	if (!ch)
		return ERR_PTR(-ENOMEM);

	return ch;
}

static inline void crypto_free_shash(struct crypto_shash *tfm)
{
	kfree(tfm);
}

static inline unsigned int crypto_shash_digestsize(struct crypto_shash *tfm)
{
	return 4;
}

static inline int crypto_shash_init(struct shash_desc *desc)
{
	desc->crc = 0xffffffff;

	return 0;
}

static inline int crypto_shash_update(struct shash_desc *desc,
				      uint8_t *data,
				      unsigned int nbytes)
{
	desc->crc = crc32c(desc->crc, data, nbytes);

	return 0;
}

static inline int crypto_shash_final(struct shash_desc *desc, uint8_t *out)
{
	*((uint32_t*)out) = ~(desc->crc);

	return 0;
}

static inline void shash_desc_zero(struct shash_desc *desc)
{
	desc->crc = 0;
}

static inline int crypto_shash_get_flags(struct crypto_shash *h)
{
	return 0;
}

#endif
