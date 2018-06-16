# Note: this works only when there is no filesytem on the device.
windrbd-test.exe --gtest_filter=windrbd.do_read_past\* --expected-size=52387840 --drive=K:
