# Tests for WinDRBD 1.2 branch

## Manual tests

### I/O for 72 hours

Unconnected. Ran with f88ad220eb149fd (I think) on Windows

### Primary / Secondary for 24 hours

No sleep in between but also no I/O
Unconnected on Windows, Connected on ReactOS.
Ran with 76547832377 (removing device in PnP handler)
ReactOS: almost 50000 iterations (then some timer locked the system)
Windows: 23749 iterations

Update: re-run after cleanup of primary/secondary code
	(create/destroy Windows device)
Version: windrbd-1.2.0-rc6-76-g81df2298-pnp-cleaned-up17-drbd-9.0-x86_64
32050 iterations on Windows (unconnected) about 26 hours

### Disconnect / Connect / Wait-Connect / Sleep 30

When invalidated so it syncs a bit goal is to trigger free_page BSOD

### invalidate / wait-sync

On Windows (with 27GB disk): 59 iterations (about 20 hours)
	with windrbd-1.2.0-rc6
	Were there any connection losses?

Dec 5-6 2024: with 2b417f71733a28de no connection losses
	82 iterations about 20 hours

### I/O for 16 hours connected, with drbd-9.1

Dec 9-10 2024: Ran fio with b17ee402 on Windows (compiled against DRBD 9.1)

Stats:
  WRITE: bw=25.3MiB/s (26.6MB/s), 6363KiB/s-6569KiB/s (6516kB/s-6727kB/s), io=14
25GiB (1530GB), run=57600000-57600033msec

### disconnect / connect / wait-connect

Dec 27-28: with cdc87c08 for drbd-9.1 (but checked 9.0 and 9.2 also)
	18226 iterations (in about 22 hours)
	With focus on execution speed (average 5 seconds / run but
	reconnect sometimes takes > 10sec, which is probably also on
	Linux DRBD). So I would say fast enough.
