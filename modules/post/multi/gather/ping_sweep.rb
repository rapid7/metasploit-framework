##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Multi Gather Ping Sweep',
        'Description' => %q{ Performs IPv4 ping sweep using the OS included ping command.},
        'License' => MSF_LICENSE,
        'Author' => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform' => %w[bsd linux osx solaris win],
        'SessionTypes' => [ 'meterpreter', 'shell' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
    register_options(
      [
        OptAddressRange.new('RHOSTS', [true, 'IP Range to perform ping sweep against.']),
      ]
    )
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
        if !ipa
          break
        end

        iplst << ipa
      end

      case session.platform
      when 'windows'
        count = ' -n 1 '
        cmd = 'ping'
      when 'solaris'
        cmd = '/usr/sbin/ping'
      else
        count = ' -n -c 1 -W 2 '
        cmd = 'ping'
      end

      ip_found = []

      while !iplst.nil? && !iplst.empty?
        a = []
        1.upto session.max_threads do
          a << framework.threads.spawn("Module(#{refname})", false, iplst.shift) do |ip_add|
            next if ip_add.nil?

            if session.platform =~ /solaris/i
              r = cmd_exec(cmd, "-n #{ip_add} 1")
            else
              r = cmd_exec(cmd, count + ip_add)
            end
            if r =~ /(TTL|Alive)/i
              print_good "\t#{ip_add} host found"
              ip_found << ip_add
            else
              vprint_status("\t#{ip_add} host not found")
            end
          end
        end
        a.map(&:join)
      end
    rescue Rex::TimeoutError, Rex::Post::Meterpreter::RequestError
      vprint_error(e.message)
    rescue StandardError => e
      print_status("The following error was encountered: #{e.class} #{e}")
    end

    ip_found.each do |ip|
      report_host(host: ip)
    end
  end
end
