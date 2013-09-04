#!/usr/bin/env ruby
#
# $Id$
#
# This script generates module changelogs
#
# $Revision$
#

msfbase = __FILE__
while File.symlink?(msfbase)
	msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', 'lib')))
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require 'rex'
require 'msf/ui'
require 'msf/base'


def usage
	$stderr.puts "#{$0} <src rev> [dst rev]"
	exit(0)
end

src_rev = ARGV.shift || usage()
dst_rev = ARGV.shift || "HEAD"

$stderr.puts "[*] Extracting changes from Subversion..."
data = `svn diff -r #{src_rev}:#{dst_rev} --summarize https://www.metasploit.com/svn/framework3/trunk/modules/`

# Always disable the database (we never need it just to list module
# information).
framework_opts = { 'DisableDatabase' => true }

# Initialize the simplified framework instance.
framework = Msf::Simple::Framework.create(framework_opts)


madd = []
mdel = []
mmod = []

data.each_line do |line|

	action, mname = line.strip.split(/\s+/, 2)
	mname = mname.gsub(/^.*modules\//, '').gsub('exploits', 'exploit').gsub(/\.rb$/, '')
	case action
	when /^A/
		# Added a new module
		m = framework.modules.create(mname)
		if m
			madd << "\"#{m.name}\":http://www.metasploit.com/modules/#{mname}"
		end
	when /^D/
		# Deleted a module
		mdel << mname
	when /^M/
		# Modified a module
		# Added a new module
		m = framework.modules.create(mname)
		if m
			mmod << "\"#{m.name}\":http://www.metasploit.com/modules/#{mname}"
		end
	end

end


$stdout.puts "h2. New Modules\n\n"
madd.each { |x| $stdout.puts x }
$stdout.puts "\nh2. Modified Modules\n\n"
mmod.each { |x| $stdout.puts x }
$stdout.puts "\nh2. Removed Modules\n\n"
mdel.each { |x| $stdout.puts "* modules/#{x}" }

