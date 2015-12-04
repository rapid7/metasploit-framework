##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'          => 'Windows Antivirus Excluded Locations Enumeration',
        'Description'   => 'This module will enumerate all excluded directories within supported AV products',
        'License'       => MSF_LICENSE,
        'Author'        => [
          'Andrew Smith', # original metasploit module
          'Jon Hart <jon_hart[at]rapid7.com>' # improved metasploit module
        ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      )
    )

    register_options(
      [
        OptBool.new('DEFENDER', [true, 'Enumerate exclusions for Microsoft Defener', true]),
        OptBool.new('ESSENTIALS', [true, 'Enumerate exclusions for Microsoft Security Essentials/Antimalware', true]),
        OptBool.new('SEP', [true, 'Enumerate exclusions for Symantec Endpoint Protection (SEP)', true])
      ]
    )
  end

  DEFENDER_BASE_KEY = 'HKLM\\SOFTWARE\\Microsoft\\Windows Defender'
  ESSENTIALS_BASE_KEY = 'HKLM\\SOFTWARE\\Microsoft\\Microsoft Antimalware'
  SEP_BASE_KEY = 'HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection'

  def av_installed?(base_key, product)
    if registry_key_exist?(base_key)
      print_status("Found #{product}")
      true
    else
      false
    end
  end

  def excluded_sep
    print_status "Excluded Locations:"
    keyadm = "HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Exclusions\\ScanningEngines\\Directory\\Admin"
    if (found_keysadm = registry_enumkeys(keyadm))
      found_keysadm.each do |vals|
        full = keyadm + "\\" + vals
        values = registry_getvaldata(full, "DirectoryName")
        print_good "#{values}"
      end
    else
      print_error "No Admin Locations Found"
    end

    keycli = "HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Exclusions\\ScanningEngines\\Directory\\Client"
    if (found_keyscli = registry_enumkeys(keycli))
      found_keyscli.each do |vals|
        full = keycli + "\\" + vals
        values = registry_getvaldata(full, "DirectoryName")
        print_good "#{values}"
      end
    else
      print_error "No Client Locations Found"
    end
  end

  def excluded_mssec
    print_status "Excluded Locations:"
    keyms = "HKLM\\SOFTWARE\\Microsoft\\Microsoft Antimalware\\Exclusions\\Paths\\"
    if (found = registry_enumvals(keyms))
      found.each do |num|
        print_good "#{num}"
      end
    else
      print_error "No Excluded Locations Found"
    end
  end

  def excluded_defender
    print_status "Excluded Locations:"
    keyms = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\"
    if (found = registry_enumvals(keyms))
      found.each do |num|
        print_good "#{num}"
      end
    else
      print_error "No Excluded Locations Found"
    end
  end

  def setup
    unless datastore['DEFENDER'] || datastore['ESSENTIALS'] || datastore['SEP']
      fail_with(Failure::BadConfig, 'Must set one or more of DEFENDER, ESSENTIALS or SEP to true')
    end
  end

  def run
    if sysinfo['Architecture'] =~ /WOW64/
      print_error "You are running this module from a 32-bit process on a 64-bit machine. Migrate to a 64-bit process and try again"
      return
    end

    print_status("Enumerating Excluded Paths for AV on #{sysinfo['Computer']}")
    found = false
    if datastore['DEFENDER'] && av_installed?(DEFENDER_BASE_KEY, 'Microsoft Defender')
      found = true
      excluded_defender
    end
    if datastore['ESSENTIALS'] && av_installed?(ESSENTIALS_BASE_KEY, 'Microsoft Security Essentials / Antimalware')
      found = true
      excluded_mssec
    end
    if datastore['SEP'] && av_installed?(SEP_BASE_KEY, 'Symantec Endpoint Protection')
      found = true
      excluded_sep
    end

    print_error "No supported AV identified" unless found
  end
end
