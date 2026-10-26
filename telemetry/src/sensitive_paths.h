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

#endif
