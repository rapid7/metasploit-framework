#
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Multi Gather Resolve Hosts',
      'Description'   => %q{
        Resolves hostnames to either IPv4 or IPv6 addresses from the perspective of the remote host.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Ben Campbell <eat_meatballs[at]hotmail.co.uk>' ],
      'Platform'      => %w{ win python },
      'SessionTypes'  => [ 'meterpreter' ]
    ))

      register_options([
        OptString.new('HOSTNAMES', [true, 'Comma seperated list of hostnames to resolve.']),
        OptEnum.new('AI_FAMILY', [true, 'Address Family', 'IPv4', ['IPv4', 'IPv6'] ])
      ], self.class)
  end

  def run
    hosts = datastore['HOSTNAMES'].split(',')

    if datastore['AI_FAMILY'] == 'IPv4'
      family = AF_INET
    else
      family = AF_INET6
    end

    # Clear whitespace
    hosts.collect{|x| x.strip!}

    print_status("Attempting to resolve '#{hosts.join(', ')}' on #{sysinfo['Computer']}") if not sysinfo.nil?

    response = client.net.resolve.resolve_hosts(hosts, family)

    table = Rex::Ui::Text::Table.new(
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
