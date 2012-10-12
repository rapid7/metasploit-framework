#!/usr/bin/env ruby

msfbase = __FILE__
while File.symlink?(msfbase)
	msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), 'lib')))

require 'msf/util/switch'

start_time = Time.now.utc
@svn_switcher = Msf::Util::SvnSwitch.new

$stdout.puts "[*]"
$stdout.puts "[*] Validating the Metaspoit Framework SVN checkout."
$stdout.puts "[*]"
res = @svn_switcher.exec :cleanup_current_cmd
if res
	$stdout.puts "[*]"
	$stdout.puts "[*] Switching Metasploit Framework to the official GitHub SVN repo."
	$stdout.puts "[*] This procedure will take several minutes."
	$stdout.puts "[*]"
else
	$stdout.puts ""
	$stdout.puts "[-] Current svn checkout cannot be cleaned up, aborting."
	$stdout.puts "[-] Please check that this is an SVN checkout, and if so,"
	$stdout.puts "[-] re-run msfupdate to ensure switchability."
	$stdout.puts ""
	exit 1
end
	
$stdout.puts "[*]"
$stdout.puts ""
temp_checkout = @svn_switcher.config.new_svn_checkout
$stdout.puts "[*] Creating temporary checkout at #{temp_checkout}"
@svn_switcher.exec :checkout_cmd
$stdout.puts "[*] Staging the svn update."
@svn_switcher.exec :stage_cmd
$stdout.puts "[*] Updating contents."
@svn_switcher.exec :update_cmd
$stdout.puts "[*] Cleaning up and getting svn info"
@svn_switcher.exec :cleanup_cmd
@svn_switcher.exec :revert_cmd
@svn_switcher.exec :info_cmd
# $stdout.puts "[*] Deleting the temporary checkout."
# @svn_switcher.delete_new_svn_checkout

end_time = Time.now.utc - start_time
$stdout.puts "Time elapsed: %0.2fm" % (end_time / 60.0)
