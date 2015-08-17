##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post

  include Msf::Post::File

  def initialize
    super(
      'Name'         => 'BusyBox Ping Network',
      'Description'  => 'This module will be applied on a session connected
                         to a BusyBox sh shell. The script will ping a range of
                         ip adresses from the router or device executing BusyBox.',
      'Author'       => 'Javier Vicente Vallejo',
      'License'      => MSF_LICENSE,
      'References'   =>
        [
          [ 'URL', 'http://vallejo.cc']
        ],
      'Platform'      => ['linux'],
       'SessionTypes'  => ['shell']
    )

    register_options(
      [
        OptAddress.new('IPRANGESTART',   [ true, "The first ip address of the range to ping.", nil ]),
        OptAddress.new('IPRANGEEND',   [ true, "The last ip address of the range to ping.", nil ])
      ], self.class)
  end

  #
  #this module will send a sh script for busybox shell for doing ping to a range of ip address from
  #the router or device that is executing busybox. It could be possible to calculate each ip address
  #of the range of ip addresses in the ruby script and execute each ping command with cmd_exec, but
  #it would generate an unnecesary traffic in the connection with the busybox device (usually telnet)
  #
  def run
    sh_script_lines=[
            "#!/bin/sh",
            "param1=#{datastore['IPRANGESTART']}",
            "param2=#{datastore['IPRANGEEND']}",
            "while true;",
            "  param1cpy=\"$param1\"",
            "  pos=`expr index \"$param1cpy\" \".\"`",
            "  pos=`expr $pos - 1`",
            "  octec1=`expr substr \"$param1cpy\" 1 $pos`",
            "  pos=`expr $pos + 2`",
            "  len=`expr length \"$param1cpy\"`",
            "  param1cpy=`expr substr \"$param1cpy\" $pos $len`",
            "  pos=`expr index \"$param1cpy\" \".\"`",
            "  pos=`expr $pos - 1`",
            "  octec2=`expr substr \"$param1cpy\" 1 $pos`",
            "  pos=`expr $pos + 2`",
            "  len=`expr length \"$param1cpy\"`",
            "  param1cpy=`expr substr \"$param1cpy\" $pos $len`",
            "  pos=`expr index \"$param1cpy\" \".\"`",
            "  pos=`expr $pos - 1`",
            "  octec3=`expr substr \"$param1cpy\" 1 $pos`",
            "  pos=`expr $pos + 2`",
            "  len=`expr length \"$param1cpy\"`",
            "  param1cpy=`expr substr \"$param1cpy\" $pos $len`",
            "  octec4=\"$param1cpy\"",
            "  carry=0",
            "  len=`expr length \"$octec4\"`",
            "  temp=`expr match \"$octec4\" \"255\"`",
            "  if [ $temp -eq $len ]; then",
            "    octec4=0",
            "    carry=1",
            "  else",
            "    octec4=`expr $octec4 + 1`",
            "  fi",
            "  if [ $carry -eq 1 ]; then",
            "    carry=0",
            "    len=`expr length \"$octec3\"`",
            "    temp=`expr match \"$octec3\" \"255\"`",
            "    if [ $temp -eq $len ]; then",
            "      octec3=0",
            "      carry=1",
            "    else",
            "      octec3=`expr \"$octec3\" + 1`",
            "    fi",
            "  fi",
            "  if [ $carry -eq 1 ]; then",
            "    carry=0",
            "    len=`expr length \"$octec2\"`",
            "    temp=`expr match \"$octec2\" \"255\"`",
            "    if [ $temp -eq $len ]; then",
            "      octec2=0",
            "      carry=1",
            "    else",
            "      octec2=`expr $octec2 + 1`",
            "    fi",
            "  fi",
            "  if [ $carry -eq 1 ]; then",
            "    carry=0",
            "    len=`expr length \"$octec1\"`",
            "    temp=`expr match \"$octec1\" \"255\"`",
            "    if [ $temp -eq $len ]; then",
            "      octec1=0",
            "      carry=1",
            "    else",
            "      octec1=`expr $octec1 + 1`",
            "    fi",
            "  fi",
            "  ping -c 1 \"$param1\"",
            "  param1=\"$octec1\"\".\"\"$octec2\"\".\"\"$octec3\"\".\"\"$octec4\"",
            "  temp=`expr match \"$param1\" \"$param2\"`",
            "  len=`expr length \"$param2\"`",
            "  if [ $temp -eq $len ]; then",
            "    ping -c 1 \"$param1\"",
            "    break",
            "  fi",
            "done"
            ]

    begin
      #send script and receive echos
      count=0
      sh_script_lines.each do |sh_script_line|
        session.shell_write(sh_script_line + "\n")
        count+=1
        result=session.shell_read() #receive echos
        vprint_status(result)
        Rex::sleep(0.03)
      end
    rescue
      print_error("Problems were found while sending script to the BusyBox device.")
      return
    end
    Rex::sleep(1.00)

    full_results = ""
    begin
      #receiving ping results
      count=0
      print_status("Script has been sent to the busybox device. Doing ping to the range of addresses.")
      while count<15 #we stop when we have been 15 seconds without receiving responses
        result = session.shell_read()
        if result.length>0
          count=0
          print_status(result)
          full_results << result
        else
          vprint_status("No response.")
          count+=1
        end
        Rex::sleep(1.00)
      end
    rescue
      print_warning("Problems were found while receiving ping results. Probably remote device terminated the connection.\nResults that were already received will be kept.")
    end

    #storing results
    p = store_loot("Pingnet", "text/plain", session, full_results, "#{datastore['IPRANGESTART']}"+"-"+"#{datastore['IPRANGEEND']}", "BusyBox Device Network Range Pings")
    print_good("Pingnet results saved to #{p}.")
  end

end
