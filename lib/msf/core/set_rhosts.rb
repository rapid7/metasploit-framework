#
# Set RHOSTS in the +active_module+'s (or global if none) datastore from an array of addresses
#
# This stores all the addresses to a temporary file and utilizes the
# <pre>file:/tmp/filename</pre> syntax to confer the addrs.  +rhosts+
# should be an Array.  NOTE: the temporary file is *not* deleted
# automatically.
#
def set_rhosts_from_addrs(rhosts)
	if rhosts.empty?
		print_status "The list is empty, cowardly refusing to set RHOSTS"
		return
	end
	if active_module
		mydatastore = active_module.datastore
	else
		# if there is no module in use set the list to the global variable
		mydatastore = self.framework.datastore
	end

	if rhosts.length > 5
		# Lots of hosts makes 'show options' wrap which is difficult to
		# read, store to a temp file
		rhosts_file = Rex::Quickfile.new("msf-db-rhosts-")
		mydatastore['RHOSTS'] = 'file:'+rhosts_file.path
		# create the output file and assign it to the RHOSTS variable
		rhosts_file.write(rhosts.join("\n")+"\n")
		rhosts_file.close
	else
		# For short lists, just set it directly
		mydatastore['RHOSTS'] = rhosts.join(" ")
	end

	print_line "RHOSTS => #{mydatastore['RHOSTS']}"
	print_line
end