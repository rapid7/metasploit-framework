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
			'Name'          => 'Multi General Resolve Hosts',
			'Description'   => %q{
				Resolves hostnames.
			},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'Ben Campbell <eat_meatballs[at]hotmail.co.uk' ],
			'Platform'      => [ 'win', 'linux' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))

			register_options([
				OptString.new('HOSTNAMES', [true, 'Comma seperated list of hostnames to resolve.'])
			], self.class)
	end

	def run
		hosts = datastore['HOSTNAMES'].split(',')
		
		# Clear whitespace
		hosts.collect{|x| x.strip!}

		print_status("Attempting to resolve '#{hosts.join(', ')}' on #{sysinfo['Computer']}") if not sysinfo.nil?

		response = client.net.resolve.resolve_hosts(hosts)

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
			table << [result[:hostname], result[:ip]]
		end
		
		table.print
	end
end
