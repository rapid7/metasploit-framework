##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/common'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::Common

  OFFICE_REGISTRY_PATH = 'HKCU\\SOFTWARE\\Microsoft\\Office'
  TRUSTED_LOCATIONS_PATH = 'Security\\Trusted Locations'

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Windows Gather Microsoft Office Trusted Locations',
      'Description'   => %q( This module will enumerate the Microsoft Office trusted locations on the target host. ),
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
    locations = ""
    [REGISTRY_VIEW_64_BIT, REGISTRY_VIEW_32_BIT].each do |registry_arch|
      arch = registry_arch == REGISTRY_VIEW_64_BIT ? ARCH_X64 : ARCH_X86
      reg_keys = registry_enumkeys(OFFICE_REGISTRY_PATH, registry_arch)
      if reg_keys.nil?
        print_error("Failed to enumerate Office in #{arch} registry hive.")
        return
      end

      reg_keys.each do |version|
        next if /[0-9][0-9].0/.match(version).nil?

        print_status("Version found: #{version}")
        version_path = "#{OFFICE_REGISTRY_PATH}\\#{version}"
        applications = registry_enumkeys(version_path, registry_arch)

        if applications.nil?
          print_status('Failed to enumerate applications.')
          next
        end

        vprint_status('Found applications.')
        #find version to use
        applications.each do |application|
          trusted_locations_path = "#{version_path}\\#{application}\\#{TRUSTED_LOCATIONS_PATH}"
          trusted_locations = registry_enumkeys(trusted_locations_path, registry_arch)
          next if trusted_locations.nil?

          print_good("Found trusted locations in #{application}")
          #find version to use
          trusted_locations.each do |location|
            location_path = "#{trusted_locations_path}\\#{location}"
            description = registry_getvaldata(location_path, 'Description', registry_arch)
            allow_subfolders = registry_getvaldata(location_path, 'AllowSubFolders', registry_arch)
            path = registry_getvaldata(location_path, 'Path', registry_arch)
            vprint_status("Description: #{description}")
            result = "Application: #{application}, Path: #{path}, AllSubFolders: #{!!allow_subfolders}"
            locations << "#{result}\n"
            print_status(result)
          end
        end
      end
      path = store_loot('host.trusted_locations', 'text/plain', session, locations, 'trusted_locations.txt', 'Trusted Locations')
      print_good("Results stored in: #{path}")
    end
  end
end
