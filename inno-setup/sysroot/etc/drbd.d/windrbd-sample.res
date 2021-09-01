# This is a sample configuration for windrbd with 2 nodes
# For commercial support please contact office@linbit.com

include "global_common.conf";

resource "windrbd-sample" {
	protocol	A;

	net {
		use-rle no;
	}

# Use this for faster sync speed:
#	disk {
#		c-max-rate 4048000;
#		c-fill-target 1048000;
#	}

	on linuxhost {
		address		192.168.0.2:7600;
		node-id 1;
		volume 1 {
# For Linux use /dev notation
			disk		/dev/sdb1;
			device		/dev/drbd1;
			meta-disk	internal;
		}
	}
	on windowshost {
		address		192.168.0.3:7600;
		node-id 2;
		volume 1 {
# The backing device of the DRBD volume
#			disk		"E:";
#
# However we strongly recommend not to assign drive letters to
# backing devices and use GUID's to address Windows volumes instead
# You can find them with the mountvol utility.
#
			disk            "3e56b893-10bf-11e8-aedd-0800274289ab";
#
# Meta disk can be internal or external
			meta-disk	internal;
#			meta-disk	"G:";
# Again, we recommend not to use a drive letter:
#			meta-disk       "3e56b893-10bf-11e8-aedd-080027421234";
#
# Device is Just an unique minor (for this host). Do not specify a
# drive letter here any more since that interface (block device) is
# deprecated # (MSSQL Server for example won't run). We now are accessing data
# via a SCSI disk interface. Once the resource is Primary an additional
# disk should appear in the Partition Manager (to be started from
# Control Panel) where it can be partioned and the partitions can
# be formatted and assigned a drive letter there.
#
			device		minor 1;
#
# Please note that Linux drbd-utils versions before 9.7.0 do not
# understand the WinDRBD syntax of block devices, so you need to
# either upgrade your drbd-utils on Linux to 9.7.0 (recommended)
# or replace the disk, device and meta-disk windows block devices
# with dummy values (/dev/drbdX, /dev/sdxx) if you want to use
# the same file on Linux.
#
		}
	}
}
