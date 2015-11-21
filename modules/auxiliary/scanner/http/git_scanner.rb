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
        OptString.new('TARGETURI', [true, 'The test path to .git directory', '/.git/']),
        OptBool.new('GIT_INDEX', [true, 'Check index file in .git directory', true]),
        OptBool.new('GIT_CONFIG', [false, 'Check config file in .git directory', true]),
        OptBool.new('GIT_HEAD', [false, 'Check HEAD file in .git directory', true])
      ]
    )
  end

  def req(filename)
    send_request_cgi(
      'uri' => normalize_uri(target_uri, filename)
    )
  end

  def git_index_parse(resp)
    return if resp.blank? || resp.length < 12 # A 12-byte header
    signature = resp[0, 4]
    return unless signature == 'DIRC'

    version = resp[4, 4].unpack('N')[0].to_i
    entries_count = resp[8, 4].unpack('N')[0].to_i

    return unless version && entries_count
    print_good("#{full_uri} (git repo version #{version}) - #{entries_count} files found")

    report_note(
      host: rhost,
      port: rport,
      proto: 'tcp',
      type: 'git_disclosure',
      data: { full_uri: full_uri, version: version, entries_count: entries_count }
    )
  end

  def git_index
    res = req('index')
    return unless res && res.code == 200
    git_index_parse(res.body)
  end

  def git_config
    res = req('config')
    return unless res && res.code == 200

    if (res.body.include?('core') || res.body.include?('remote') || res.body.include?('branch'))
      print_good("#{full_uri} (git disclosure - config file Found")

      report_note(
        host: rhost,
        port: rport,
        proto: 'tcp',
        type: 'git_disclosure',
        data: { full_uri: full_uri }
      )
    end
  end

  def git_head
    res = req('HEAD')
    return unless res && res.code == 200

    if res.body.include?('ref:')
      print_good("#{full_uri} (git disclosure - HEAD file Found")

      report_note(
        host: rhost,
        port: rport,
        proto: 'tcp',
        type: 'git_disclosure',
        data: { full_uri: full_uri }
      )
    end
  end

  def run_host(_target_host)
    vprint_status("#{full_uri} - scanning git disclosure")
    vhost = datastore['VHOST'] || wmap_target_host
    git_index if datastore['GIT_INDEX']
    git_config if datastore['GIT_CONFIG']
    git_head if datastore['GIT_HEAD']
  end
end
