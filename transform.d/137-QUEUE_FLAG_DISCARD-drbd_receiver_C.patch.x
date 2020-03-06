diff --git a/drbd/drbd_receiver.c b/drbd/drbd_receiver.c
index 13ec23c..955d6be 100644
--- a/drbd/drbd_receiver.c
+++ b/drbd/drbd_receiver.c
@@ -1305,7 +1305,7 @@ int drbd_issue_discard_or_zero_out(struct drbd_device *device, sector_t start, u
 
 static bool can_do_reliable_discards(struct drbd_device *device)
 {
-#ifdef QUEUE_FLAG_DISCARD
+#if 0
 	struct request_queue *q = bdev_get_queue(device->ldev->backing_bdev);
 	struct disk_conf *dc;
 	bool can_do;
