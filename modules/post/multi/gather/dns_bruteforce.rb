##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'


class Metasploit3 < Msf::Post

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Multi Gather DNS Forward Lookup Bruteforce',
        'Description'   => %q{
          Brute force subdomains and hostnames via wordlist.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform'      => %w{ bsd linux osx solaris win },
        'SessionTypes'  => [ 'meterpreter', 'shell' ]
      ))
    register_options(
      [

        OptString.new('DOMAIN', [true, 'Domain to do a fordward lookup bruteforce against.']),
        OptPath.new('NAMELIST',[true, "List of hostnames or subdomains to use.",
            ::File.join(Msf::Config.data_directory, "wordlists", "namelist.txt")])

      ], self.class)
  end

  # Run Method for when run command is issued
  def run

    domain = datastore['DOMAIN']
    hostlst = datastore['NAMELIST']
    a = []

    print_status("Performing DNS Forward Lookup Bruteforce for Domain #{domain}")
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

    name_list = []
    if ::File.exists?(hostlst)
      ::File.open(hostlst).each do |n|
        name_list << n
      end
    end

    platform = session.platform

    case platform
    when /win/i
      cmd = "nslookup"
    when /solaris/i
      cmd = "/usr/sbin/host "
    else
      cmd = "/usr/bin/host "
    end
    while(not name_list.nil? and not name_list.empty?)
      1.upto(thread_num) do
        a << framework.threads.spawn("Module(#{self.refname})", false, name_list.shift) do |n|
          next if n.nil?
          vprint_status("Trying #{n.strip}.#{domain}")
          r = cmd_exec(cmd, "#{n.strip}.#{domain}")

          case session.platform
          when /win/
            proccess_win(r, "#{n.strip}.#{domain}")
          else
            process_nix(r, "#{n.strip}.#{domain}")
          end
        end
        a.map {|x| x.join }
      end
    end
  end

  # Process the data returned by nslookup
  def proccess_win(data,ns_opt)
    if data =~ /Name/
      # Remove unnecessary data and get the section with the addresses
      returned_data = data.split(/Name:/)[1]
      # check each element of the array to see if they are IP
      returned_data.gsub(/\r\n\t |\r\n|Aliases:|Addresses:/," ").split(" ").each do |e|
        if Rex::Socket.dotted_ip?(e)
          print_good("#{ns_opt} #{e}")
          report_host(:host=>e, :name=>ns_opt.strip)
        end
      end
    end
  end

  # Process the data returned by the host command
  def process_nix(r,ns_opt)
    r.each_line do |l|
      data = l.scan(/(\S*) has address (\S*)$/)
      if not data.empty?
        data.each do |e|
          print_good("#{ns_opt} #{e[1]}")
          report_host(:host=>e[1], :name=>ns_opt.strip)
        end
      end
    end
  end
end
