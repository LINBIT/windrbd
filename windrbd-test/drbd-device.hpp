struct params {
	const char *drive;
	unsigned long long expected_size;
	bool force;
	const char *dump_file;
};

extern struct params p;
