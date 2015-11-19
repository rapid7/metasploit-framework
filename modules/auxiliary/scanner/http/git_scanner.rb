##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'HTTP Git Scanner',
      'Description' => 'Detect Git disclosure.',
      'Author'      => ['Nixawk'],
      'References'  => [
        ['URL', 'https://github.com/git/git/blob/master/Documentation/technical/index-format.txt']
      ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The test path to .git directory', '/'])
      ], self.class)
  end

  def peer
    "#{rhost}:#{rport}"
  end

  def git_url(url)
    normalize_uri(url, '/.git/index')
  end

  def git_index_parse(resp)
    return if resp.blank? || resp.length < 12 # A 12-byte header
    standard_signature = 'DIRC'
    signature = resp[0, 4]
    return if signature != standard_signature

    version = resp[4, 8].unpack('N')[0].to_i
    entries_number = resp[8, 12].unpack('N')[0].to_i

    return unless version && entries_number
    vprint_status("Git Version: #{version} -  Entries Number: #{entries_number}")
    print_good("#{peer} - Git Entries file found")

    report_note(
      host: rhost,
      port: rport,
      proto: 'tcp',
      type: 'git_disclosure',
      data: { version: version, entries_number: entries_number }
    )
  end

  def git_entries(url)
    res = send_request_cgi({
      'uri' => git_url(url)
    })
    return unless res && res.code == 200
    git_index_parse(res.body)
  end

  def run_host(target_host)
    vprint_status("#{peer} - scanning git disclosure")
    vhost = datastore['VHOST'] || wmap_target_host
    git_entries(normalize_uri(target_uri.path))
  end
end
