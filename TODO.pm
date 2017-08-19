
* Check ULONG_PTR which ones need to be 64bit on 64bit arch
    * simply changing all means that we'd break 32bit - would we want/need to support that?

* Change kmem_cache_alloc etc. to "Lookaside Lists"
    https://msdn.microsoft.com/en-us/library/windows/hardware/ff565416(v=vs.85).aspx

* WriteSame not supported

* Thin should be supported?
    https://msdn.microsoft.com/en-us/windows/hardware/drivers/storage/thin-provisioning

* receiver wakeup (signals, for ping)

* transport_tcp:
    It can not be derived from the Linux transport_tcp. The WinSock API is very
    different from the Linux TCP API. Simply take mantech's edition and ripp out
    all the useless #ifdefs.

* Mantech's submit_bio doesn't run bio_endio() on failure?

* Timeouts, SND_BUFF etc.?
	+#define DRBD_SNDBUF_SIZE_MAX  (1024*1024*1024*2)
	+#define DRBD_SNDBUF_SIZE_DEF  (1024*1024*20)


########################### done ####################


* RCU -- okay for Phil 9f2ece44099531b6d0155414386a4c1e04426ce6
