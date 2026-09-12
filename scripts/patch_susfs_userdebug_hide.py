#!/usr/bin/env python3
"""Inject AOSP userdebug type hiding into the susfs SELinux hooks.

When susfs is present it provides its own my_write_context / my_write_access /
my_setprocattr hooks in the kernel, which makes ReSukiSU compile out its own
selinux_hide hooks (KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE). The susfs hooks
only serve backup_sepolicy and do not filter the AOSP userdebug types, so add
the same su/su_exec/su_file/adbroot filtering here.

Run from the kernel common/ directory after applying the susfs 50_ patch.
"""

import sys

HELPER = r'''
/*
 * AOSP userdebug builds ship the su/su_exec/adbroot types while user builds
 * do not; hide them from the policy exposed to apps.
 */
static bool is_aosp_userdebug_type(const char *scontext, size_t len)
{
	static const char *const hidden_types[] = { "su", "su_exec", "su_file", "adbroot", "adbroot_exec" };
	const char *end = scontext + len;
	const char *type_start = NULL;
	const char *type_end = end;
	const char *p;
	int field = 0;
	size_t i;

	for (p = scontext; p < end; p++) {
		if (*p != ':')
			continue;
		field++;
		if (field == 2) {
			type_start = p + 1;
		} else if (field == 3) {
			type_end = p;
			break;
		}
	}

	if (!type_start)
		return false;

	for (i = 0; i < ARRAY_SIZE(hidden_types); i++) {
		size_t type_len = type_end - type_start;
		if (type_len == strlen(hidden_types[i]) && !strncmp(type_start, hidden_types[i], type_len))
			return true;
	}

	return false;
}
'''


def patch(path, helper_anchor, replacements):
    with open(path) as f:
        src = f.read()

    if 'is_aosp_userdebug_type' in src:
        print(f'{path}: already patched, skipping')
        return

    if helper_anchor not in src:
        sys.exit(f'{path}: helper anchor not found')

    src = src.replace(helper_anchor, HELPER + '\n' + helper_anchor, 1)

    for old, new in replacements:
        if old not in src:
            sys.exit(f'{path}: replacement anchor not found: {old[:70]!r}')
        src = src.replace(old, new, 1)

    with open(path, 'w') as f:
        f.write(src)
    print(f'{path}: patched')


patch(
    'security/selinux/selinuxfs.c',
    'static ssize_t my_write_context(struct file *file, char *buf, size_t size)\n{',
    [
        (
            '\t\treturn sel_write_context(file, buf, size);\n',
            '\t\treturn sel_write_context(file, buf, size);\n\n'
            '\tif (is_aosp_userdebug_type(buf, size))\n'
            '\t\treturn -EINVAL;\n',
        ),
        (
            '\tlength = security_context_to_sid_with_policy(backup_sepolicy, scon, strlen(scon), &ssid, SECSID_NULL, GFP_KERNEL);\n',
            '\tif (is_aosp_userdebug_type(scon, strlen(scon)) || is_aosp_userdebug_type(tcon, strlen(tcon)))\n'
            '\t\tgoto out;\n\n'
            '\tlength = security_context_to_sid_with_policy(backup_sepolicy, scon, strlen(scon), &ssid, SECSID_NULL, GFP_KERNEL);\n',
        ),
    ],
)

patch(
    'security/selinux/hooks.c',
    'static int my_setprocattr(const char *name, void *value, size_t size)\n{',
    [
        (
            '\t\terror = security_context_to_sid_with_policy(backup_sepolicy, str, size, &sid, SECSID_NULL, GFP_KERNEL);\n',
            '\t\tif (is_aosp_userdebug_type(str, size))\n'
            '\t\t\treturn -EINVAL;\n\n'
            '\t\terror = security_context_to_sid_with_policy(backup_sepolicy, str, size, &sid, SECSID_NULL, GFP_KERNEL);\n',
        ),
    ],
)
