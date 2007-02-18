#!/usr/bin/env ruby

banner =
%q{##
# $Id:$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

}

mod  = ARGV.shift
data = File.read(mod)

if (data =~ /This file is part of the Metasploit/) {
	exit(0)
}


fd = File.open(mod, 'w')
fd.write(banner)
fd.write(data)
fd.close

system("svn propset svn:keywords 'Rev Revision Id Header' #{mod}")


