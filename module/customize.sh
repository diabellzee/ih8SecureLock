#!/system/bin/sh

if [ -n "$KSU" ]; then
	ui_print "* KernelSU detected. Make sure you are using a Zygisk module!"
elif [ "$ZYGISK_ENABLED" != "1" ]; then
	# Checked only in the plain-Magisk branch above: Magisk's own developer
	# docs guarantee ZYGISK_ENABLED=1 is set when Zygisk is on, but under
	# KernelSU that same guarantee doesn't hold the same way -- Zygisk
	# support there comes through a separate bridge (e.g. ZygiskNext),
	# which may not populate this variable identically. Advisory only,
	# does not abort: a false negative here just costs the user an
	# ignorable warning, while aborting on a wrong assumption could block
	# a perfectly legitimate install.
	ui_print "* WARNING: Zygisk does not appear to be enabled."
	ui_print "* This module requires Zygisk to do anything."
	ui_print "* Enable it in Magisk settings, then reboot."
fi

ui_print "* Do not put the apps for which you want to take an ss"
ui_print "* in any kind of denylist and disable 'Unmount modules'"
ui_print "* option for them"


ui_print ""
ui_print "  by j-hc (github.com/j-hc)"
