# paste the linker output into this:
sed -e '/undefined/!d' -e "s/^.*\`\\([a-zA-Z0-9_@]*\\)'.*$/\\1/g" | sort | uniq
