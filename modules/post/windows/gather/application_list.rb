##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post

	include Msf::Post::Registry

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'List installed applications',
			'Description'   => %q{
				This module lists installed applications and their versions
				using the registry.
			},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
			'Version'       => '$Revision$',
			'Platform'      => [ 'windows' ],
			#'Passive'       => true,
			'SessionTypes'  => [ 'meterpreter', 'shell' ]
		))
		@ltype = 'generic.environment'
	end

	def run
		appkeys = [
			'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
			'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
			'HKLM\\SOFTWARE\\WOW6432NODE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
			'HKCU\\SOFTWARE\\WOW6432NODE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
			]

		tbl = Rex::Ui::Text::Table.new(
			'Header'  => "Installed Applications",
			'Indent'  => 1,
			'Columns' =>
			[
				"Name",
				"Version"
			])

		threadnum = 0
		a = []
		appkeys.each do |keyx86|
			registry_enumkeys(keyx86).each do |k|
				if threadnum < 10
					a.push(::Thread.new {
							begin
								dispnm = registry_getvaldata("#{keyx86}\\#{k}","DisplayName")
								dispversion = registry_getvaldata("#{keyx86}\\#{k}","DisplayVersion")
								tbl << [dispnm,dispversion] if dispnm and dispversion
							rescue
							end
						})
					threadnum += 1
				else
					sleep(0.05) and a.delete_if {|x| not x.alive?} while not a.empty?
					threadnum = 0
				end
			end
		end
		print_line tbl.to_s
	end

end


