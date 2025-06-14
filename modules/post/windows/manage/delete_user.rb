##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Accounts

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Manage Local User Account Deletion',
        'Description' => %q{
          This module deletes a local user account from the specified server,
          or the local machine if no server is given.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'chao-mu'],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [SERVICE_RESOURCE_LOSS],
          'SideEffects' => [CONFIG_CHANGES],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('USERNAME', [ true, 'The username of the user to delete (not-qualified, e.g. BOB)' ]),
        OptString.new('SERVER_NAME', [ false, 'DNS or NetBIOS name of remote server on which to delete user' ]),
      ]
    )
  end

  def run
    username = datastore['USERNAME']
    target_server = datastore['SERVER_NAME']

    status = delete_user(username, target_server || nil)

    case status
    when :success
      print_status 'User was deleted!'
    when :invalid_server
      print_error 'The server you specified was invalid'
    when :not_on_primary
      print_error 'You must be on the primary domain controller to do that'
    when :user_not_found
      print_error 'User did not exist!'
    when :access_denied
      print_error 'Sorry, you do not have permission to delete that user'
    when nil
      print_error 'Could not delete user. Something horrible just happened. Sorry.'
    else
      print_error 'This module is out of date'
    end
  end
end
