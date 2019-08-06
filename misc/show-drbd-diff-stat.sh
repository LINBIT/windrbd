echo -n "Total lines changed: "
diff -r drbd converted-sources | grep '^[<>]' | wc -l
echo -n "Lines added: "
diff -r drbd converted-sources | grep '^>' | wc -l
echo -n "Lines removed: "
diff -r drbd converted-sources | grep '^<' | wc -l

