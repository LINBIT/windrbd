struct params {
	const char *drive;
	unsigned long long expected_size;
	bool force;
	const char *dump_file;
	unsigned long long request_size;
};

extern struct params p;
