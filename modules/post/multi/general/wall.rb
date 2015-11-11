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
      ], self.class)
  end

  def cowsay(text)
    # cowsay(1) chunks a message up into 39-byte chunks and wraps it in '| ' and ' |'
    # Rex::Text.wordwrap(text, 0, 39, ' |', '| ') almost does this, but won't
    # split a word that has > 39 characters in it which results in oddly formed
    # text in the cowsay banner, so just do it by hand
    text_lines = text.scan(/.{1,34}/)
    max_length = text_lines.map(&:size).sort.last
    cloud_parts = []
    cloud_parts << " #{'_' * (max_length + 2)} "
    if text_lines.size == 1
      cloud_parts << "< #{text} >"
    else
      cloud_parts << "/ #{text_lines.first.ljust(max_length, ' ')} \\"
      if text_lines.size > 2
        text_lines[1, text_lines.length - 2].each do |line|
          cloud_parts << "| #{line.ljust(max_length, ' ')} |"
        end
      end
      cloud_parts << "\\ #{text_lines.last.ljust(max_length, ' ')} /"
    end
    cloud_parts << " #{'-' * (max_length + 2)} "
    cloud_parts << <<EOS
       \\   ,__,
        \\  (oo)____
           (__)    )\\
              ||--|| *
EOS
    cloud_parts.join("\n")
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

    datastore['COWSAY'] ? cowsay(text) : text
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
