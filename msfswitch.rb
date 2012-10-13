#!/usr/bin/env ruby


start_time = Time.now.utc

msfbase = __FILE__
while File.symlink?(msfbase)
	msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), 'lib')))

require 'msf/util/switch'
require 'msf/util/svn'
unless Msf::Util::SVN.root =~ /\.metasploit\.com/
	$stdout.puts "[-] This is not an anonymous SVN checkout, aborting."
	exit 1
end

@svn_switcher = Msf::Util::SvnSwitch.new(1234)

$stdout.puts "[*]"
$stdout.puts "[*] Switching Metasploit Framework to the official GitHub SVN repo."
$stdout.puts "[*] This procedure will take several minutes."
$stdout.puts "[*]"
$stdout.puts ""
temp_checkout = @svn_switcher.config.new_svn_checkout
$stdout.puts "[*] Prepping current checkout #{@svn_switcher.config.msfbase}"
unless @svn_switcher.system :cleanup_current_cmd
	$stdout.puts "[-] Error with svn cleanup, aborting!"
	exit 2
end

$stdout.puts "[*] Enumerating untracked files"
FileUtils.mkdir temp_checkout rescue nil
@svn_switcher.create_untracked_files_list

$stdout.puts "[*] Creating temporary checkout at #{temp_checkout}"
@svn_switcher.system :checkout_cmd
$stdout.puts "[*] Staging the svn update."
@svn_switcher.system :stage_cmd
$stdout.puts "[*] Updating contents."
@svn_switcher.system :update_cmd
$stdout.puts "[*] Cleaning up"
@svn_switcher.system :cleanup_cmd
@svn_switcher.system :revert_cmd
@svn_switcher.system :info_cmd
$stdout.puts "[*] Preserving untracked files"
@svn_switcher.copy_untracked_files do |x|
	puts x.inspect
end
# $stdout.puts "[*] Deleting the temporary checkout."
# @svn_switcher.delete_new_svn_checkout

end_time = Time.now.utc - start_time
$stdout.puts "[*] Time elapsed: %0.2fm" % (end_time / 60.0)
