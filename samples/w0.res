# This is just an example how a drbd.conf for 
# WinDRBD could look like. Place it into /etc/drbd.d
# and include it from /etc/drbd.conf
#
# To get professional support for WinDRBD please go
# to www.linbit.com

resource "w0" {
	protocol	A;

	net {
		use-rle no;
	}

	on ubuntu-gnome {
		address		192.168.56.103:7626;
		node-id 1;
		volume 17 {
			disk		/dev/ram0;
			device		/dev/drbd26;
			flexible-meta-disk	internal;
		}
	}

	on linbit-wdrbd {
		address		192.168.56.101:7626;
		node-id 2;
		volume 17 {
			disk	"0b098289-8295-11e7-bddb-0800274272c4";
# For now this means DRBD device will be H:
			device		/dev/drbd5;
			meta-disk	internal;
		}
	}
}
