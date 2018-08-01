#include "gtest/gtest.h"
#include "drbd-device.hpp"
#include <getopt.h>
#include <string.h>

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
			{"dump-file", required_argument, 0, 'o'},
			{"request-size", required_argument, 0, 'r'},
			{"mode", required_argument, 0, 'm'},
			{"stop-on-error", no_argument, 0, 'e'},
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
		case 'o':
			printf("Dumpfile is %s\n", optarg);
			p.dump_file = optarg;
			break;
		case 'r':
			p.request_size = atoll(optarg);
			printf("Request size (for 1meg test) is %lld (instead of 1meg)\n", p.request_size);
			break;
		case 'm':
			if (strchr(optarg, 'r') != NULL)
				if (strchr(optarg, 'w') != NULL)
					p.mode = MODE_WRITE_AND_READ;
				else
					p.mode = MODE_ONLY_READ;
			else
				if (strchr(optarg, 'w') != NULL)
					p.mode = MODE_ONLY_WRITE;
				else
					printf("mode must contain r and/or w (defaulting to both)\n");
			break;
		case 'e':
			p.stop_on_error = 1;
			break;

		default:
			printf("unknown argument: %c\n", c);
		}
	}

	return RUN_ALL_TESTS();
}
