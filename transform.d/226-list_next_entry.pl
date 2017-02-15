#!/usr/bin/perl -pi.bak

s{list_next_entry\(req, tl_requests\)}
 {list_next_entry\(struct drbd_request, req, tl_requests\)};
