$res = "rds_resource"
$minor = 1

$c = [cultureinfo]::GetCultureInfo('en-EN')

$synced = [decimal]-1
$stalled = 0

$suspended = $false

while ($true) {
	$s = drbdadm status $res

	$syncing = $False
	foreach ($l in $s) {
		if ($l -match'replication:SyncSource.*done:([0-9.]*)') {
			$syncing = $true

			$d = [decimal]::Parse($matches[1], $c)
			if ($d -eq $synced) {
				$stalled++
				echo "sync stalled at $d ($stalled) ..."
			} else {
				$stalled = 0
			}
			if ($stalled -eq 10) {
				echo "sync still stalled, trying to suspend io"
				windrbd suspend-io-for-minor $minor
				$suspended = $true
			}
			if ($stalled -eq 20) {
				echo "sync still stalled, suspend-io did not work, we should escalate now"
				windrbd resume-io-for-minor $minor
				$suspended = $false
			}

			$synced = $d
		}
	} 
	if (!$syncing -and $suspended) {
		windrbd resume-io-for-minor $minor
		$suspended = $false
	}
	sleep 1
}
