##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
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
        'Author'        => [
          'Jon Hart <jon_hart[at]rapid7.com>' # original metasploit module
        ],
        # TODO: is there a way to do this on Windows?
        'Platform'      => %w(linux osx unix),
        'SessionTypes'  => %w(shell meterpreter)
      )
    )
    register_options(
      [
        OptString.new('MESSAGE', [false, 'The message to send', '']),
        OptString.new('USERS', [false, 'List of users to write(1) to, separated by commas. ' \
                      ' wall(1)s to all users by default']),
        OptBool.new('COWSAY', [true, 'Display MESSAGE in a ~cowsay way', false])
      ])
  end

  def users
    datastore['USERS'] ? datastore['USERS'].split(/\s*,\s*/) : nil
  end

  def message
    if datastore['MESSAGE'].blank?
      text = "Hello from a metasploit session at #{Time.now}"
    else
      text = datastore['MESSAGE']
    end

    datastore['COWSAY'] ? Rex::Text.cowsay(text) : text
  end

  def run
    if users
      # this requires that the target user has write turned on
      users.map { |user| cmd_exec("echo '#{message}' | write #{user}") }
    else
      # this will send the messages to all users, regardless of whether or
      # not they have write turned on.  If the session is root, the -n will disable
      # the annoying banner
      cmd_exec("echo '#{message}' | wall -n")
    end
  end
end
