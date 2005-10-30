module Msf

###
#
# TcpConnSweep
# ------------
#
# This recon module discovers hosts by doing a simple TCP connection attempt
# to a specific port.
#
###
class Recon::Host::PortScanner::TcpConnSweep < Msf::Recon::Discoverer::Host

	def initialize(info = {})
		super(merge_info(info,
			'Name'           => 'TCP Connection Sweeper',
			'Description'    => %q{
				This module discovers hosts by doing a simple TCP connection
				sweep on a given port.
			},
			'Author'         => 'skape',
			'Version'        => '$Revision$'))

		# Register the remote port option requirement
		register_options(
			[
				Opt::RPORT
			], Msf::Recon::Host::PortScanner::TcpConnSweep)
	end

	# 
	# Probes for the presence of a host by establishing a simple TCP connection
	# to it on the specified port.
	#
	def probe_host(ip)
		begin
			# If we get a socket, then we connected.  Report the host as being
			# alive.
			if (sock = Rex::Socket::Tcp.create(
				'PeerHost'  => ip,
				'PeerPort'  => datastore['RPORT'].to_i,
				'LocalHost' => datastore['CHOST'] || '0.0.0.0',
				'LocalPort' => datastore['CPORT'] ? datastore['CPORT'].to_i : 0))
				[ 
					'state'      => HostState::Alive, 
					'connection' => sock 
				]
			end
		# If we get connection refused, then we are indirectly determining that
		# the host is alive.
		rescue Rex::ConnectionRefused
			HostState::Alive
		# Any other exception is a sign of failure, but we can't say that it's
		# dead.
		rescue
			HostState::Unknown
		end
	end

	#
	# Cleans up 
	#
	def probe_host_cleanup(ip, state)
		state['Connection'].close
	end

end

end
