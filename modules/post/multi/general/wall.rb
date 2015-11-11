##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'          => 'Write Messages to Users',
        'Description'   => %q{
          This module utilizes the wall(1) or write(1) utilities, as appropriate,
          to send messages to users on the target system.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Jon Hart <jon_hart[at]rapid7.com>' ],
        # TODO: is there a way to do this on Windows?
        'Platform'      => %w(linux osx unix),
        'SessionTypes'  => %w(shell meterpreter)
      )
    )
    register_options(
      [
        OptString.new('MESSAGE', [true, 'The message to send']),
        OptString.new('USERS', [false, 'List of users to write(1) to, separated by commas. ' \
                      ' wall(1)s to all users by default'])
      ], self.class)
  end

  def users
    datastore['USERS'] ? datastore['USERS'].split(/\s*,\s*/) : nil
  end

  def message
    datastore['MESSAGE'] ? datastore['MESSAGE'] : "Hello metasploit session #{session.id}, the time is #{Time.now}"
  end

  def run
    if users
      users.map { |user| cmd_exec("echo '#{message}' | write #{user}") }
    else
      cmd_exec("echo '#{message}' | wall")
    end
  end
end
