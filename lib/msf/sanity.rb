#
# Provides some sanity checks against the ruby build and version
#


# Check for the broken pack/unpack in OS X 10.4.x
if ([1].pack('n') == "\x01\x00")
	puts "*** This ruby build has a broken pack/unpack implementation! "
	
	if (RUBY_PLATFORM =~ /darwin/)
		puts "    Apple shipped a broken version of ruby with the 10.4.x   "
		puts "    release. Please install ruby from source, or use one of  "
		puts "    the free package managers to obtain a working ruby build."
	end
	
	exit(0)
end

# Check for ruby 1.8.3 as the minimal supported version
if (RUBY_VERSION =~ /^1\.[0-7]\./ or RUBY_VERSION =~ /^1\.8\.[0-2]$/)
	puts "*** This version of ruby is not supported, please upgrade to 1.8.3+"
	exit(0)
end
