/*
   drbd_proc.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

   drbd is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   drbd is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with drbd; see the file COPYING.  If not, write to
   the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

 */
#include <linux/seq_file.h>
#include "drbd_int.h"

int drbd_seq_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "WDRBD:%s\nLDRBD: " REL_VERSION " (api:%d/proto:%d-%d)\n",
		drbd_buildtag(),GENL_MAGIC_VERSION, PRO_VERSION_MIN, PRO_VERSION_MAX);
	drbd_print_transports_loaded(seq);

	return 0;
}
