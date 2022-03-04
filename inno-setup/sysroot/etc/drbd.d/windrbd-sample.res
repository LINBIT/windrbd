# This is a sample configuration for windrbd with 2 Windows nodes
# For commercial support please contact office@linbit.com
#
# To learn how to setup WinDRBD with 2 (or more) Windows/Linux
# nodes please go to www.linbit.com and download the user's
# guides from https://linbit.com/user-guides/ (WinDRBD User's
# guide and maybe DRBD 9.0 User's guide for advanced settings).

include "global_common.conf";

resource "windrbd-sample" {
	protocol C;

	on windowshost1 {
		address		192.168.0.2:7600;
		node-id 1;
		volume 1 {
			disk		"E:";
# Or you can also use the GUID if you are short on drive letters. Use
# mountvol to find the GUIDs of the backing device.
#			disk            "3e56b893-10bf-11e8-aedd-0800274289ab";
#
# Meta disk can be internal or external
			meta-disk	internal;
#			meta-disk	"G:";
# Again, also GUID is possible
#			meta-disk       "3e56b893-10bf-11e8-aedd-080027421234";
# Minor must be usique on this host.
			device		minor 1;
		}
	}

	on windowshost2 {
		address		192.168.0.3:7600;
		node-id 2;
		volume 1 {
			disk		"E:";
			meta-disk	internal;
			device		minor 1;
		}
	}

# Note that you can also add Linux resources:
#        on linuxhost {
#                address         192.168.0.4:7600;
#                node-id 3;
#                volume 1 {
## For Linux use /dev notation
#                        disk            /dev/sdb1;
#                        device          /dev/drbd1;
#                        meta-disk       internal;
#                }
#        }
}
