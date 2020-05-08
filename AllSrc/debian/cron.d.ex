#
# Regular cron jobs for the loki package
#
0 4	* * *	root	[ -x /usr/bin/loki_maintenance ] && /usr/bin/loki_maintenance
