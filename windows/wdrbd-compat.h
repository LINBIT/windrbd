

#define BIO_ENDIO_ARGS(b,e) (b,e)

#define MODULE_AUTHOR(egal, ...)
#define MODULE_DESCRIPTION(egal, ...)
#define MODULE_VERSION(egal)
#define MODULE_LICENSE(egal)
#define MODULE_PARM_DESC(egal, ...)

#define module_param(...)


struct kmem_cache {
	NPAGED_LOOKASIDE_LIST cache;
};


#define BIO_ENDIO_ARGS(void1, void2) (void *p1, void *p2, void *p3)
