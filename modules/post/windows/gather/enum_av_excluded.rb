##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Registry

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Antivirus Excluded Locations Enumeration',
        'Description'   => %q{ This module will enumerate all excluded directories within supported AV products },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Andrew Smith'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))

  end

  def enum_mssec
    if registry_enumkeys("HKLM\\SOFTWARE\\Microsoft").include?("Microsoft Antimalware")
        print_status "MS Security Essentials Identified"
        return true
    else
        return false
    end
  rescue
    return false
  end
  def enum_defender
    if registry_enumkeys("HKLM\\SOFTWARE\\Microsoft").include?("Windows Defender")
        print_status "Windows Defender Identified"
        return true
    else
        return false
    end
  rescue
    return false
  end

  def enum_sep
    if registry_enumkeys("HKLM\\SOFTWARE\\Symantec").include?("Symantec Endpoint Protection")
        print_status "SEP Identified"
        return true
    else
        return false
    end
  rescue
    return false 
  end
  def excluded_sep
    print_status "Excluded Locations:"
    keyadm = "HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Exclusions\\ScanningEngines\\Directory\\Admin"
    keycli = "HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Exclusions\\ScanningEngines\\Directory\\Client"
        found_keysadm = registry_enumkeys(keyadm)
        if found_keysadm
            found_keysadm.each do |vals|
                full = keyadm + "\\" + vals
                values = registry_getvaldata(full, "DirectoryName")
                print_good "#{values}"
            end
        else
            print_error "No Admin Locations Found"
        end
        found_keyscli = registry_enumkeys(keycli)
        if found_keyscli
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
    keyms  = "HKLM\\SOFTWARE\\Microsoft\\Microsoft Antimalware\\Exclusions\\Paths\\"
    found = registry_enumvals(keyms)
    if found
       found.each do |num|
           print_good "#{num}"
       end
    else
       print_error "No Excluded Locations Found"
    end
  end
  def excluded_defender
    print_status "Excluded Locations:"
    keyms  = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\"
    found = registry_enumvals(keyms)
    if found
       found.each do |num|
           print_good "#{num}"
       end
    else
       print_error "No Excluded Locations Found"
    end
  end

  def run
    arch2 = sysinfo['Architecture']
    if arch2 =~ /WOW64/
        print_error "You are running this module from a 32-bit process on a 64-bit machine. Migrate to a 64-bit process and try again"
        return
    else
        print_status("Enumerating Excluded Paths for AV on #{sysinfo['Computer']}")
        
        if enum_sep
            excluded_sep
        else
            nosep = true
        end
        if enum_mssec
            excluded_mssec
        else
            nomssec = true
        end
        if enum_defender
            excluded_defender
        else
            nodefend = true
        end
        if nomssec and nodefend and nosep == true
            print_error "No supported AV identified"
        end
    end
  end
end
