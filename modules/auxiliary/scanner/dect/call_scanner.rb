require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::DECT_COA
	
	def initialize
		super(
			'Name'           => 'DECT Call Scanner',
			'Version'        => '$Revision$',
			'Description'    => 'This module scans for active DECT calls',
			'Author'         => [ 'DK <privilegedmode@gmail.com>' ],
			'License'        => MSF_LICENSE,
			'References'     => [ ['Dedected', 'http://www.dedected.org'] ]
		)	
		register_options([
			OptString.new('VERBOSE',[false, 'Print out verbose information during the scan', true])
		],  self.class )
	end

	def print_results
		print_line("Time\t\t\t\tRFPI\t\tChannel")
		@calls.each do |rfpi, data|
			print_line("#{data['time']}\t#{data['rfpi']}\t#{data['channel']}")
		end	
	end


=begin
	def record_call(data)
		print_status("Synchronizing..")
		pp_scan_mode(data['rfpi_raw'])
		while(true)
			data = poll_coa()
			puts data
		end	
	end
=end

	def run
		@calls = {}

		print_status("Opening interface: #{datastore['INTERFACE']}")
		print_status("Using band: #{datastore['band']}")
		
		open_coa
		
		begin

			print_status("Changing to call scan mode.")
			call_scan_mode
			print_status("Scanning...")

			while (true)
				data = poll_coa()
				if (data)
					parsed_data = parse_call(data)
					parsed_data['time'] = Time.now
					print_status("Found active call on: #{parsed_data['rfpi']}")
					@calls[parsed_data['time']] = parsed_data
				end

				next_channel

				if (datastore['VERBOSE'])
					print_status("Switching to channel: #{channel}")
				end
				sleep(1)
			end
		ensure
			print_status("Closing interface")
			stop_coa()
			close_coa()
		end
		
		print_results
	end
end
