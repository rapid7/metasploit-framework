module Msf

###
#
# This module provides methods for reporting data to the DB
#
###

module Auxiliary::Report


	module HttpClients
		IE = "MSIE"
		FF = "Firefox"
		SAFARI = "Safari"
		OPERA  = "Opera"

		UNKNOWN = "Unknown"
	end
	module OperatingSystems
		LINUX   = "Linux"
		MAC_OSX = "MacOSX"
		WINDOWS = "Windows"

		module WindowsVersions
			XP    = "XP"
			TWOK  = "2000"
			TWOK3 = "2003"
			VISTA = "Vista"
		end

		UNKNOWN = "Unknown"
	end


	# Shortcut method for detecting when the DB is active
	def db
		framework.db.active
	end

	#
	# Report a host's liveness and attributes such as operating system and service pack
	#
	# opts must contain :host, which is an IP address identifying the host
	# you're reporting about
	#
	# See data/sql/*.sql and lib/msf/core/db.rb for more info
	#
	def report_host(opts)
		return if not db
		addr = opts[:host] || return

		framework.db.queue Proc.new {
			framework.db.report_host_state(self, addr, Msf::HostState::Alive)
			host = nil

			opts.delete(:host)
			if (opts.length > 0)
				host = framework.db.report_host(self, addr, opts)
			end
		}
	end

	def get_host(addr)
		return nil if not db
		framework.db.get_host(self, addr)
	end

	#
	# Report a client connection
	#
	# opts must contain
	#	:host      the address of the client connecting
	#	:ua_string a string that uniquely identifies this client
	# opts can contain
	#	:ua_name a brief identifier for the client, e.g. "Firefox"
	#	:ua_ver  the version number of the client, e.g. "3.0.11"
	#
	def report_client(opts={})
		return if not db
		addr = opts.delete(:host) || return

		framework.db.queue Proc.new {
			framework.db.report_host_state(self, addr, Msf::HostState::Alive)
			cli = framework.db.report_client(self, addr, opts)
		}
	end

	def get_client(addr, ua_string)
		return nil if not db
		framework.db.get_client(self, addr, ua_string)
	end

	#
	# Report detection of a service
	#
	def report_service(opts={})
		return if not db
		addr  = opts[:host]  || return
		port  = opts[:port]  || return
		proto = opts[:proto] || 'tcp'
		name  = opts[:name]
		state = opts[:state] || 'open'
		info  = opts[:info]
		hname = opts[:host_name]
		maddr = opts[:host_mac]

		framework.db.queue Proc.new {
			framework.db.report_host_state(self, addr, Msf::HostState::Alive)

			serv = framework.db.report_service_state(
				self,
				addr,
				proto,
				port,
				state
			)

			changed = false
			if(hname)
				self.host.name = hname
				changed = true
			end

			if(maddr)
				self.host.mac = maddr
				changed = true
			end
			serv.host.save! if changed


			changed = false
			if (name and name.length > 1)
				serv.name = name.downcase
				changed = true
			end

			if (info and info.length > 1)
				serv.info = info
				changed = true
			end

			serv.save! if changed
		}
	end

	def report_note(opts={})
		return if not db
		addr  = opts[:host]  || return
		ntype = opts[:type]  || return
		data  = opts[:data]  || return

		framework.db.queue Proc.new {
			host  = framework.db.report_host_state(self, addr, Msf::HostState::Alive)
			note  = framework.db.get_note(self, host, ntype, data)
		}
	end

	def report_vuln_service(opts={})
		return if not db

		framework.db.queue Proc.new {
			serv = report_service(opts)
			return if not serv

			vname = opts[:vname]
			vdata = opts[:vdata] || ''

			host = serv.host
			vuln = framework.db.get_vuln(self, host, serv, vname, vdata)

			framework.db.vuln_add_refs(self, vuln, opts[:refs])
		}
	end

	def report_vuln_host(opts={})
		return if not db
		addr  = opts[:host]  || return

		framework.db.queue Proc.new {
			host  = framework.db.report_host_state(self, addr, Msf::HostState::Alive)
			vname = opts[:vname]
			vdata = opts[:vdata] || ''

			vuln = framework.db.get_vuln(self, host, nil, vname, vdata)

			framework.db.vuln_add_refs(self, vuln, opts[:refs])
		}
	end

	def report_auth_info(opts={})
		return if not db
		addr  = opts[:host]   || return
		data  = opts[:proto]  || return

		opts[:type] = "auth_#{opts[:proto]}"
		opts[:data] =
			"AUTH #{ opts[:targ_host] || 'unknown' }:#{ opts[:targ_port] || 'unknown' } " +
			"#{opts[:user] || "<NULL>"} #{opts[:pass] || "<NULL>" } #{opts[:extra]}"
		print_status("Recording successful #{data} credentials for #{addr}")
		report_note(opts)
	end

	def find_note(host, ntype)
		return if not db
		framework.db.find_note(host, ntype)
	end


end
end

