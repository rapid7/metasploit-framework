module Msf

###
#
# Nmap
# ----
#
# This recon modules uses nmap to detect the services that are running on a
# given host.
#
# TODO:
#
#   - switch to using -oX -
#
###
class Recon::Service::PortScanner::Nmap < Msf::Recon::Discoverer::Service

	def initialize(info = {})
		super(merge_info(info,
			'Name'           => 'Nmap port scanner',
			'Description'    => %q{
				This module uses nmap to detect the services that are running 
				on a given host.
			},
			'Author'         => 'skape',
			'Version'        => '$Revision$'))
	end

	#
	# This method checks to ensure that nmap is installed on this machine in
	# some form or another.
	#
	def self.is_usable
		(Rex::FileUtils.find_full_path('nmap') != nil)	
	end

	def probe_host(host)
		# If we are running as root, use nmap to do a SYN scan
		if (Process.euid == 0)
			cmd = "nmap -sS #{host.address}"
		# Otherwise, if we're non-root, use the standard tcp connect() scan
		else
			cmd = "nmap -sT #{host.address}"
		end

		# Fire it off...
		p = IO.popen(cmd)

		begin
			# Read each line, extracting the ones that contain open port
			# information
			while (buf = p.gets)
				if (buf =~ /^(\d+)\/(tcp|udp)\s+open/i)
					report_service_state(host, $2, $1, ServiceState::Up)
				end
			end
		ensure
			p.close
		end
	end

	##
	#
	# Automated launching
	#
	##

	include Msf::ReconEvent::HostSubscriber

	#
	# This method is automatically called when a new host is found.
	#
	def on_new_host(context, host)
		# TODO: check if auto-service-probe should be enabled
		# TODO: precedence of who should be able to search for services
		# TODO: evasion qualifications
		probe_host(host)
	end

end

end
