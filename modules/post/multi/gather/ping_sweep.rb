##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Multi Gather Ping Sweep',
        'Description'   => %q{ Performs IPv4 ping sweep using the OS included ping command.},
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform'      => %w{ bsd linux osx solaris win },
        'SessionTypes'  => [ 'meterpreter', 'shell' ]
      ))
    register_options(
      [

        OptAddressRange.new('RHOSTS', [true, 'IP Range to perform ping sweep against.']),

      ], self.class)
  end

  # Run Method for when run command is issued
  def run
    iprange = datastore['RHOSTS']
    print_status("Performing ping sweep for IP range #{iprange}")
    iplst = []
    begin
      ipadd = Rex::Socket::RangeWalker.new(iprange)
      numip = ipadd.num_ips
      while (iplst.length < numip)
        ipa = ipadd.next_ip
        if (not ipa)
          break
        end
        iplst << ipa
      end
      if session.type =~ /shell/
        # Only one thread possible when shell
        thread_num = 1
        # Use the shell platform for selecting the command
        platform = session.platform
      else
        # When in Meterpreter the safest thread number is 10
        thread_num = 10
        # For Meterpreter use the sysinfo OS since java Meterpreter returns java as platform
        platform = session.sys.config.sysinfo['OS']
      end

      platform = session.platform

      case platform
      when /win/i
        count = " -n 1 "
        cmd = "ping"
      when /solaris/i
        cmd = "/usr/sbin/ping"
      else
        count = " -n -c 1 -W 2 "
        cmd = "ping"
      end

      ip_found = []

      while(not iplst.nil? and not iplst.empty?)
        a = []
        1.upto(thread_num) do
          a << framework.threads.spawn("Module(#{self.refname})", false, iplst.shift) do |ip_add|
            next if ip_add.nil?
            if platform =~ /solaris/i
              r = cmd_exec(cmd, "-n #{ip_add} 1")
            else
              r = cmd_exec(cmd, count + ip_add)
            end
            if r =~ /(TTL|Alive)/i
              print_status "\t#{ip_add} host found"
              ip_found << ip_add
            else
              vprint_status("\t#{ip_add} host not found")
            end

          end
        end
        a.map {|x| x.join }
      end
    rescue Rex::TimeoutError, Rex::Post::Meterpreter::RequestError
    rescue ::Exception => e
      print_status("The following Error was encountered: #{e.class} #{e}")
    end

    ip_found.each do |ip|
      report_host(:host => ip)
    end
  end
end
