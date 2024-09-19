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
