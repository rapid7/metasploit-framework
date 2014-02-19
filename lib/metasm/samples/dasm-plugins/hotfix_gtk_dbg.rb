#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


#
# This plugin will create a monitoring process running samples/hotfix_gtk_dbg.rb on the current process (to fix a GTK crash when closing a window)
#

mypid = Process.pid

if (!Process.fork)
	ARGV.clear
	ARGV << mypid
	$VERBOSE = false
	Kernel.load File.join(Metasmdir, 'samples', 'hotfix_gtk_dbg.rb')
	exit!
end
