##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Multi Gather Resolve Hosts',
      'Description'   => %q{
        Resolves hostnames to either IPv4 or IPv6 addresses from the perspective of the remote host.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Ben Campbell' ],
      'Platform'      => %w{ win python },
      'SessionTypes'  => [ 'meterpreter' ]
    ))

      register_options([
        OptString.new('HOSTNAMES', [false, 'Comma seperated list of hostnames to resolve.']),
        OptPath.new('HOSTFILE', [false, 'Line separated file with hostnames to resolve.']),
        OptEnum.new('AI_FAMILY', [true, 'Address Family', 'IPv4', ['IPv4', 'IPv6'] ])
      ])
  end

  def run

    hosts = []
    if datastore['HOSTNAMES']
      hostnames = datastore['HOSTNAMES'].split(',')
      hostnames.each do |hostname|
        hostname.strip!
          hosts << hostname unless hostname.empty?
      end
    end

    if datastore['HOSTFILE']
      ::File.open(datastore['HOSTFILE'], "rb").each_line do |hostname|
         hostname.strip!
         hosts << hostname unless hostname.empty?
      end
    end

    if hosts.empty?
      fail_with(Failure::BadConfig, "No hostnames to resolve.")
    end

    hosts.uniq!

    if datastore['AI_FAMILY'] == 'IPv4'
      family = AF_INET
    else
      family = AF_INET6
    end

    print_status("Attempting to resolve '#{hosts.join(', ')}' on #{sysinfo['Computer']}") if sysinfo

    response = client.net.resolve.resolve_hosts(hosts, family)

    table = Rex::Text::Table.new(
      'Indent' => 0,
      'SortIndex' => -1,
      'Columns' =>
      [
        'Hostname',
        'IP',
      ]
    )

    response.each do |result|
      if result[:ip].nil?
        table << [result[:hostname], '[Failed To Resolve]']
      else
        table << [result[:hostname], result[:ip]]
      end
    end

    table.print
  end
end
