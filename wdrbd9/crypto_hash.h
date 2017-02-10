#ifndef _WDRBD_CRYPTO_HASH_H
#define _WDRBD_CRYPTO_HASH_H

#include <wdm.h>


#define CRYPTO_ALG_ASYNC 4711
#define CRYPTO_ALG_TYPE_HASH CRYPTO_ALG_TYPE_DIGEST

struct crypto_shash {
	struct crypto_tfm *base;
	const u8 *key;
	int keylen;
};

struct hash_desc {
	struct crypto_shash *tfm;
	u32 flags;
};

static inline struct crypto_shash *
crypto_alloc_shash(const char *alg_name, u32 type, u32 mask)
{
	struct crypto_shash *ch;
	static const char supported[] = "crc32c";
	const supported_len = sizeof(supported);

	if (RtlCompareMemory(alg_name, supported, supported_len) != supported_len)
		return ERR_PTR(-ENOTSUPP);

	ch = kmalloc(sizeof(struct crypto_shash), GFP_KERNEL, 'HSWD');
	if (!ch)
		return ERR_PTR(-ENOMEM);

	return ch;
}

static inline int
crypto_hash_setkey(struct crypto_shash *hash, const u8 *key, unsigned int keylen)
{
	hash->key = key;
	hash->keylen = keylen;

	return 0;
}

static inline int
crypto_hash_digest(struct hash_desc *desc, struct scatterlist *sg,
		   unsigned int nbytes, u8 *out)
{
#if 0
	// TODO reimplement!
	crypto_hmac(desc->tfm->base, (u8 *)desc->tfm->key,
		    &desc->tfm->keylen, sg, 1 /* ! */ , out);
	/* ! this is not generic. Would need to convert nbytes -> nsg */
#endif
	return 0;
}

static inline void crypto_free_ahash(struct crypto_shash *tfm)
{
	if (!tfm)
		return;

	kfree(tfm);
}

static inline unsigned int crypto_shash_digestsize(struct crypto_shash *tfm)
{
	return crypto_tfm_alg_digestsize(tfm->base);
}

static inline struct crypto_tfm *crypto_hash_tfm(struct crypto_shash *tfm)
{
	return tfm->base;
}

static inline int crypto_hash_init(struct hash_desc *desc)
{
	return 0;
}

static inline int crypto_hash_update(struct hash_desc *desc,
				     struct scatterlist *sg,
				     unsigned int nbytes)
{
	*(int*)desc = crc32c(0, (uint8_t *)sg, nbytes);
	return 0;
}

static inline int crypto_hash_final(struct hash_desc *desc, u8 *out)
{
	int i;
	u8 *p = (u8*)desc;
	for(i = 0; i < 4; i++)
	{
		*out++ = *p++; // long
	}
	return 0;
}


#define crypto_ahash			crypto_shash
#define crypto_ahash_digestsize		crypto_shash_digestsize
#define crypto_alloc_ahash		crypto_alloc_shash

#endif
