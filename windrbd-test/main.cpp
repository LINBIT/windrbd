#include "gtest/gtest.h"
#include "drbd-device.hpp"
#include <getopt.h>

int main(int argc, char** argv)
{
	::testing::InitGoogleTest(&argc, argv);

	int c;
	int option_index;

	while (1) {
		static struct option my_options[] = {
			{"drive", required_argument, 0, 'd'},
			{"expected-size", required_argument, 0, 's'},
			{"force", no_argument, 0, 'f'},
			{0, 0, 0, 0}
		};
		c = getopt_long(argc, argv, "d:s:f", my_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 0:	/* options without a single letter variant */
//			printf("option index: %d optarg: %s\n", option_index, optarg);
			break;
		case 'd':
			printf("Drive is %s\n", optarg);
			p.drive = optarg;
			break;
		case 's':
			p.expected_size = atoll(optarg);
			printf("Expected size is %lld\n", p.expected_size);
			break;
		case 'f':
			p.force = true;
			break;
		default:
			printf("unknown argument: %c\n", c);
		}
	}

	return RUN_ALL_TESTS();
}
