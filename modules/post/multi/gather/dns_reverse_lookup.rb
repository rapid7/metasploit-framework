##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Multi Gather DNS Reverse Lookup Scan',
        'Description'   => %q{
          Performs DNS reverse lookup using the OS included DNS query command.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform'      => %w{ bsd linux osx solaris win },
        'SessionTypes'  => [ 'meterpreter', 'shell' ]
      ))
    register_options(
      [

        OptAddressRange.new('RHOSTS', [true, 'IP Range to perform reverse lookup against.'])

      ], self.class)
  end

  # Run Method for when run command is issued
  def run
    iprange = datastore['RHOSTS']
    print_status("Performing DNS Reverse Lookup for IP range #{iprange}")
    iplst = []

    a = []
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
      cmd = "nslookup"
    when /solaris/i
      cmd = "/usr/sbin/host"
    else
      cmd = "/usr/bin/host"
    end
    while(not iplst.nil? and not iplst.empty?)
      1.upto(thread_num) do
        a << framework.threads.spawn("Module(#{self.refname})", false, iplst.shift) do |ip_add|
          next if ip_add.nil?
          r = cmd_exec(cmd, " #{ip_add}")
          case platform
          when /win/
            if r =~ /(Name)/
              r.scan(/Name:\s*\S*\s/) do |n|
                hostname = n.split(":    ")
                print_good "\t #{ip_add} is #{hostname[1].chomp("\n")}"
                report_host({
                  :host => ip_add,
                  :name => hostname[1].strip
                  })
              end
            else
              vprint_status("#{ip_add} does not have a Reverse Lookup Record")
            end
          else
            if r !~ /not found/i
              hostname = r.scan(/domain name pointer (\S*)\./).join
              print_good "\t #{ip_add} is #{hostname}"
              report_host({
                  :host => ip_add,
                  :name => hostname.strip
                })
            else
              vprint_status("#{ip_add} does not have a Reverse Lookup Record")
            end
          end
        end
        a.map {|x| x.join }
      end
    end
  end
end
