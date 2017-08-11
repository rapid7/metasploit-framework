##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

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

        OptString.new('DOMAIN', [true, 'Domain to do a forward lookup bruteforce against.']),
        OptPath.new('NAMELIST',[true, "List of hostnames or subdomains to use.",
            ::File.join(Msf::Config.data_directory, "wordlists", "namelist.txt")])

      ])
  end

  # Run Method for when run command is issued
  def run
    domain = datastore['DOMAIN']
    hostlst = datastore['NAMELIST']
    a = []

    print_status("Performing DNS Forward Lookup Bruteforce for Domain #{domain}")

    name_list = []
    if ::File.exist?(hostlst)
      ::File.open(hostlst).each do |n|
        name_list << n
      end
    end

    case session.platform
    when 'windows'
      cmd = "nslookup"
    when 'solaris'
      cmd = "/usr/sbin/host "
    else
      cmd = "/usr/bin/host "
    end

    while !name_list.nil? && !name_list.empty?
      1.upto session.max_threads  do
        a << framework.threads.spawn("Module(#{self.refname})", false, name_list.shift) do |n|
          next if n.nil?
          vprint_status("Trying #{n.strip}.#{domain}")
          r = cmd_exec(cmd, "#{n.strip}.#{domain}")

          case session.platform
          when 'windows'
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
