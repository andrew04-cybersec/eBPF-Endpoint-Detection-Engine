/*paths that produce file_open events and also edit the lists here to change the filter*/
#ifndef TELEMETRY_SENSITIVE_PATHS_H
#define TELEMETRY_SENSITIVE_PATHS_H

/*whole path must match*/
#define SENSITIVE_EXACT(X) \
	X("/etc/shadow") \
	X("/etc/gshadow") \
	X("/etc/passwd") \
	X("/etc/sudoers")

/*path must start with the entry*/
#define SENSITIVE_PREFIX(X) \
	X("/etc/sudoers.d/") \
	X("/root/.ssh/")

/*any path of the form /home/<user>/.ssh/ is also matched which is in is_sensitive()*/

/*
write-intent list that is kept apart from the list above because this is a path that matches only this list and is reported only when the open flags ask for write access because these paths are opened as read-only all the time
if a first letter after the leading slash is added here then the gate in is_write_intent_path() has to list it as well
*/

#define WRITE_INTENT_EXACT(X) \
	X("/etc/ld.so.preload") \
	X("/etc/crontab") \
	X("/etc/rc.local") \
	X("/etc/profile") \
	X("/etc/bash.bashrc")

#define WRITE_INTENT_PREFIX(X) \
	X("/etc/cron.d/") \
	X("/etc/cron.hourly/") \
	X("/etc/cron.daily/") \
	X("/etc/cron.weekly/") \
	X("/etc/cron.monthly/") \
	X("/var/spool/cron/") \
	X("/etc/systemd/system/") \
	X("/usr/lib/systemd/system/") \
	X("/lib/systemd/system/") \
	X("/etc/init.d/") \
	X("/etc/profile.d/") \
	X("/etc/ld.so.conf.d/") \
	X("/etc/pam.d/") \
	X("/etc/update-motd.d/")

/*names directly under /root/ or directly under /home/<user>/ and the whole name must match*/
#define WRITE_INTENT_HOME_EXACT(X) \
	X(".bashrc") \
	X(".bash_profile") \
	X(".bash_login") \
	X(".profile") \
	X(".bash_logout") \
	X(".zshrc")

/*prefixes under /root/ or /home/<user>/ */
#define WRITE_INTENT_HOME_PREFIX(X) \
	X(".config/systemd/user/") \
	X(".config/autostart/")

#endif
