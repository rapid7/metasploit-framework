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
      'Description' => %q(
        This module can detect information disclosure vlnerabilities in
        Git Repository. Git has some files that stores in Git Resitory,
        ex: .git/config, .git/index. We can get a number of personal/
        preferences settings from .git/config, and get source code,
        account information from .git/index.
    ),
      'Author'      => [
        'Nixawk', # module developer
        'Jon Hart <jon_hart[at]rapid7.com>' # improved metasploit module
      ],
      'References'  => [
        ['URL', 'https://github.com/git/git/blob/master/Documentation/technical/index-format.txt']
      ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The test path to .git directory', '/.git/']),
        OptBool.new('GIT_INDEX', [true, 'Check index file in .git directory', true]),
        OptBool.new('GIT_CONFIG', [true, 'Check config file in .git directory', true])
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
    unless res
      vprint_error("#{full_uri}index - No response received")
      return
    end
    vprint_status("#{full_uri}index (http status #{res.code})")

    git_index_parse(res.body) if res.code == 200
  end

  def git_config
    res = req('config')
    unless res
      vprint_error("#{full_uri}config - No response received")
      return
    end
    vprint_status("#{full_uri}config - (http status #{res.code})")

    return unless res.code == 200 && res.body =~ /\[(?:branch|core|remote)\]/
    print_good("#{full_uri}config (git disclosure - config file Found)")

    report_note(
      host: rhost,
      port: rport,
      proto: 'tcp',
      type: 'git_disclosure',
      data: { full_uri: full_uri }
    )

    path = store_loot('config', 'text/plain', rhost, res.body, full_uri)
    print_good("Saved file to: #{path}")
  end

  def run_host(_target_host)
    vprint_status("#{full_uri} - scanning git disclosure")
    git_index if datastore['GIT_INDEX']
    git_config if datastore['GIT_CONFIG']
  end
end
