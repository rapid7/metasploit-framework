##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Gather External IP',
			'Description'   => %q{
				Module to get the external IP address from the command-line.},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'Borja Merino <bmerinofe[at]gmail.com>'],
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ],
			'References'    => [
				[ 'URL', 'http://superuser.com/questions/165986/windows-command-that-returns-external-ip' ]
			]
		))
		register_options(
		[
			OptString.new('SERVICE', [true, 'Website.', 'http://icanhazip.com'])
		], self.class)
	end


	def run
		vbs_file = create_vbs(datastore['SERVICE'])
		return if vbs_file.nil?

		output = cmd_exec("cscript",vbs_file)
		output.each_line do |l|
			print_good("#{l}") if l =~ /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/
		end
		file_rm(vbs_file)
	end


	def create_vbs(service)
		vbs_dir = expand_path("%TEMP%")
		vbs_file = vbs_dir << "\\" << Rex::Text.rand_text_alpha((rand(8)+6)) << ".vbs"

		conf_conn =  "Dim msf\r\n"
		conf_conn += "Set msf = CreateObject(\"MSXML2.XMLHTTP\")\r\n"
		conf_conn += "msf.open \"GET\", \"#{service}\", False\r\n"
		conf_conn += "msf.send\r\n"
		conf_conn += "WScript.StdOut.Write msf.responseText\r\n"

		if write_file(vbs_file,conf_conn)
			return vbs_file
		else
			print_error("There were problems creating the vbs file.")
			return nil
		end
	end
end
