enum test_mode {
	MODE_ONLY_READ,
	MODE_ONLY_WRITE,
	MODE_WRITE_AND_READ
};

struct params {
	const char *drive;
	unsigned long long expected_size;
	bool force;
	const char *dump_file;
	unsigned long long request_size;
	enum test_mode mode;
	int stop_on_error;
};

extern struct params p;
