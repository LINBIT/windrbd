for i in TODO.*
do
	t=$( grep TODO: $i | wc -l | tr -d \\n )
	g=$( grep TODO: $i | grep -v GNU | wc -l | tr -d \\n )
	echo -e $i:\\t$t\\t$g
done
