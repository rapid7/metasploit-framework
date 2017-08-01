##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'HTTP Git Scanner',
      'Description' => %q(
        This module can detect situations where there may be information
        disclosure vulnerabilities that occur when a Git repository is made
        available over HTTP.
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
        OptBool.new('GIT_CONFIG', [true, 'Check config file in .git directory', true]),
        OptString.new('UserAgent', [ true, 'The HTTP User-Agent sent in the request', 'git/1.7.9.5' ])
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
    [version, entries_count]
  end

  def git_index
    res = req('index')
    index_uri = git_uri('index')
    unless res
      vprint_error("#{index_uri} - No response received")
      return
    end
    vprint_status("#{index_uri} - HTTP/#{res.proto} #{res.code} #{res.message}")

    return unless res.code == 200
    version, count = git_index_parse(res.body)
    return unless version && count
    print_good("#{full_uri} - git repo (version #{version}) found with #{count} files")

    report_note(
      host: rhost,
      port: rport,
      proto: 'tcp',
      type: 'git_index_disclosure',
      data: { uri: index_uri, version: version, entries_count: count }
    )
  end

  def git_config
    res = req('config')
    config_uri = git_uri('config')
    unless res
      vprint_error("#{config_uri} - No response received")
      return
    end
    vprint_status("#{config_uri} - HTTP/#{res.proto} #{res.code} #{res.message}")

    return unless res.code == 200 && res.body =~ /\[(?:branch|core|remote)\]/
    print_good("#{config_uri} - git config file found")

    report_note(
      host: rhost,
      port: rport,
      proto: 'tcp',
      type: 'git_config_disclosure',
      data: { uri: config_uri }
    )

    path = store_loot('config', 'text/plain', rhost, res.body, config_uri)
    print_good("Saved file to: #{path}")
  end

  def git_uri(path)
    full_uri =~ %r{/$} ? "#{full_uri}#{path}" : "#{full_uri}/#{path}"
  end

  def run_host(_target_host)
    vprint_status("#{full_uri} - scanning git disclosure")
    git_index if datastore['GIT_INDEX']
    git_config if datastore['GIT_CONFIG']
  end
end
