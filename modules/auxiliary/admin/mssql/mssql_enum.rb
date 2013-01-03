##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::MSSQL
	include Msf::Auxiliary::Report

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Microsoft SQL Server Configuration Enumerator',
			'Description'    => %q{
					This module will perform a series of configuration audits and
				security checks against a Microsoft SQL Server database. For this
				module to work, valid administrative user credentials must be
				supplied.
			},
			'Author'         => [ 'Carlos Perez <carlos_perez [at] darkoperator.com>' ],
			'License'        => MSF_LICENSE
		))
	end

	def run
		print_status("Running MS SQL Server Enumeration...")

		if mssql_login_datastore == false
			print_error("Login was unsuccessful. Check your credentials.")
			disconnect
			return
		end

		# Get Version
		print_status("Version:")
		vernum =""
		ver = mssql_query("select @@version")
		sqlversion = ver[:rows].join
		sqlversion.each_line do |row|
			print "[*]\t#{row}"
		end
		vernum = sqlversion.gsub("\n"," ").scan(/SQL Server\s*(200\d)/m)
		report_note(:host => datastore['RHOST'],
			:proto => 'TCP',
			:port => datastore['RPORT'],
			:type => 'MSSQL_ENUM',
			:data => "Version: #{sqlversion}")

		#-------------------------------------------------------
		#Check Configuration Parameters and check what is enabled
		print_status("Configuration Parameters:")
		if vernum.join != "2000"
			query = "SELECT name, CAST(value_in_use AS INT) from sys.configurations"
			ver = mssql_query(query)[:rows]
			sysconfig = {}
			ver.each do |l|
				sysconfig[l[0].strip] = l[1].to_i
			end
		else
			#enable advanced options
			mssql_query("EXEC sp_configure \'show advanced options\', 1; RECONFIGURE")[:rows]
			query = "EXECUTE sp_configure"
			ver = mssql_query(query)[:rows]
			ver.class
			sysconfig = {}
			ver.each do |l|
				sysconfig[l[0].strip] = l[3].to_i
			end
		end

		#-------------------------------------------------------
		#checking for C2 Audit Mode
		if sysconfig['c2 audit mode'] == 1
			print_status("\tC2 Audit Mode is Enabled")
			report_note(:host => datastore['RHOST'],
				:proto => 'TCP',
				:port => datastore['RPORT'],
				:type => 'MSSQL_ENUM',
				:data => "C2 Audit Mode is Enabled")
		else
			print_status("\tC2 Audit Mode is Not Enabled")
			report_note(:host => datastore['RHOST'],
				:proto => 'TCP',
				:port => datastore['RPORT'],
				:type => 'MSSQL_ENUM',
				:data => "C2 Audit Mode is Not Enabled")
		end

		#-------------------------------------------------------
		#check if xp_cmdshell is enabled
		if vernum.join != "2000"
			if sysconfig['xp_cmdshell'] == 1
				print_status("\txp_cmdshell is Enabled")
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "xp_cmdshell is Enabled")
			else
				print_status("\txp_cmdshell is Not Enabled")
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "xp_cmdshell is Not Enabled")
			end
		else
			xpspexist = mssql_query("select sysobjects.name from sysobjects where name = \'xp_cmdshell\'")[:rows]
			if xpspexist != nil
				print_status("\txp_cmdshell is Enabled")
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "xp_cmdshell is Enabled")
			else
				print_status("\txp_cmdshell is Not Enabled")
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "xp_cmdshell is Not Enabled")
			end
		end

		#-------------------------------------------------------
		#check if remote access is enabled
		if sysconfig['remote access'] == 1
			print_status("\tremote access is Enabled")
			report_note(:host => datastore['RHOST'],
				:proto => 'TCP',
				:port => datastore['RPORT'],
				:type => 'MSSQL_ENUM',
				:data => "remote access is Enabled")
		else
			print_status("\tremote access is Not Enabled")
			report_note(:host => datastore['RHOST'],
				:proto => 'TCP',
				:port => datastore['RPORT'],
				:type => 'MSSQL_ENUM',
				:data => "remote access is not Enabled")
		end

		#-------------------------------------------------------
		#check if updates are allowed
		if sysconfig['allow updates'] == 1
			print_status("\tallow updates is Enabled")
			report_note(:host => datastore['RHOST'],
				:proto => 'TCP',
				:port => datastore['RPORT'],
				:type => 'MSSQL_ENUM',
				:data => "allow updates is Enabled")
		else
			print_status("\tallow updates is Not Enabled")
			report_note(:host => datastore['RHOST'],
				:proto => 'TCP',
				:port => datastore['RPORT'],
				:type => 'MSSQL_ENUM',
				:data => "allow updates is not Enabled")
		end

		#-------------------------------------------------------
		#check if Mail stored procedures are enabled
		if vernum.join != "2000"
			if sysconfig['Database Mail XPs'] == 1
				print_status("\tDatabase Mail XPs is Enabled")
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "Database Mail XPs is Enabled")
			else
				print_status("\tDatabase Mail XPs is Not Enabled")
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "Database Mail XPs is not Enabled")
			end
		else
			mailexist = mssql_query("select sysobjects.name from sysobjects where name like \'%mail%\'")[:rows]
			if mailexist != nil
				print_status("\tDatabase Mail XPs is Enabled")
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "Database Mail XPs is Enabled")
			else
				print_status("\tDatabase Mail XPs is Not Enabled")
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "Database Mail XPs is not Enabled")
			end
		end

		#-------------------------------------------------------
		#check if OLE stored procedures are enabled
		if vernum.join != "2000"
			if sysconfig['Ole Automation Procedures'] == 1
				print_status("\tOle Automation Procedures are Enabled")
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "Ole Automation Procedures are Enabled")
			else
				print_status("\tOle Automation Procedures are Not Enabled")
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "Ole Automation Procedures are not Enabled")
			end
		else
			oleexist = mssql_query("select sysobjects.name from sysobjects where name like \'%sp_OA%\'")[:rows]
			if oleexist != nil
				print_status("\tOle Automation Procedures is Enabled")
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "Ole Automation Procedures are Enabled")
			else
				print_status("\tOle Automation Procedures are Not Enabled")
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "Ole Automation Procedures are not Enabled")
			end
		end

		#-------------------------------------------------------
		# Get list of Databases on System
		print_status("Databases on the server:")
		dbs = mssql_query("select name from master..sysdatabases")[:rows].flatten
		if dbs != nil
			dbs.each do |dbn|
				print_status("\tDatabase name:#{dbn.strip}")
				print_status("\tDatabase Files for #{dbn.strip}:")
				if vernum.join != "2000"
					db_ind_files = mssql_query("select filename from #{dbn.strip}.sys.sysfiles")[:rows]
					if db_ind_files != nil
						db_ind_files.each do |fn|
							print_status("\t\t#{fn.join}")
							report_note(:host => datastore['RHOST'],
								:proto => 'TCP',
								:port => datastore['RPORT'],
								:type => 'MSSQL_ENUM',
								:data => "Database: #{dbn.strip} File: #{fn.join}")
						end
					end
				else
					db_ind_files = mssql_query("select filename from #{dbn.strip}..sysfiles")[:rows]
					if db_ind_files != nil
						db_ind_files.each do |fn|
							print_status("\t\t#{fn.join.strip}")
							report_note(:host => datastore['RHOST'],
								:proto => 'TCP',
								:port => datastore['RPORT'],
								:type => 'MSSQL_ENUM',
								:data => "Database: #{dbn.strip} File: #{fn.join}")
						end
					end
				end
			end
		end

		#-------------------------------------------------------
		# Get list of syslogins on System
		print_status("System Logins on this Server:")
		if vernum.join != "2000"
			syslogins = mssql_query("select loginname from master.sys.syslogins")[:rows]
		else
			syslogins = mssql_query("select loginname from master..syslogins")[:rows]
		end
		if syslogins != nil
			syslogins.each do |acc|
				print_status("\t#{acc.join}")
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "Database: Master User: #{acc.join}")
			end
		else
			print_error("\tCould not enumerate System Logins!")
			report_note(:host => datastore['RHOST'],
				:proto => 'TCP',
				:port => datastore['RPORT'],
				:type => 'MSSQL_ENUM',
				:data => "Could not enumerate System Logins")
		end

		#-------------------------------------------------------
		# Get list of disabled accounts on System
		if vernum.join != "2000"
			print_status("Disabled Accounts:")
			disabledsyslogins = mssql_query("select name from master.sys.server_principals where is_disabled = 1")[:rows]
			if disabledsyslogins != nil
				disabledsyslogins.each do |acc|
					print_status("\t#{acc.join}")
					report_note(:host => datastore['RHOST'],
						:proto => 'TCP',
						:port => datastore['RPORT'],
						:type => 'MSSQL_ENUM',
						:data => "Disabled User: #{acc.join}")
				end
			else
				print_status("\tNo Disabled Logins Found")
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "No Disabled Logins Found")
			end
		end

		#-------------------------------------------------------
		# Get list of accounts for which password policy does not apply on System
		if vernum.join != "2000"
			print_status("No Accounts Policy is set for:")
			nopolicysyslogins = mssql_query("select name from master.sys.sql_logins where is_policy_checked = 0")[:rows]
			if nopolicysyslogins != nil
				nopolicysyslogins.each do |acc|
					print_status("\t#{acc.join}")
					report_note(:host => datastore['RHOST'],
						:proto => 'TCP',
						:port => datastore['RPORT'],
						:type => 'MSSQL_ENUM',
						:data => "None Policy Checked User: #{acc.join}")
				end
			else
				print_status("\tAll System Accounts have the Windows Account Policy Applied to them.")
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "All System Accounts have the Windows Account Policy Applied to them")
			end
		end

		#-------------------------------------------------------
		# Get list of accounts for which password expiration is not checked
		if vernum.join != "2000"
			print_status("Password Expiration is not checked for:")
			passexsyslogins = mssql_query("select name from master.sys.sql_logins where is_expiration_checked = 0")[:rows]
			if passexsyslogins != nil
				passexsyslogins.each do |acc|
					print_status("\t#{acc.join}")
					report_note(:host => datastore['RHOST'],
						:proto => 'TCP',
						:port => datastore['RPORT'],
						:type => 'MSSQL_ENUM',
						:data => "None Password Expiration User: #{acc.join}")
				end
			else
				print_status("\tAll System Accounts are checked for Password Expiration.")
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "All System Accounts are checked for Password Expiration")
			end
		end

		#-------------------------------------------------------
		# Get list of sysadmin logins on System
		print_status("System Admin Logins on this Server:")
		if vernum.join != "2000"
			sysadmins = mssql_query("select name from master.sys.syslogins where sysadmin = 1")[:rows]
		else
			sysadmins = mssql_query("select name from master..syslogins where sysadmin = 1")[:rows]
		end
		if sysadmins != nil
			sysadmins.each do |acc|
				print_status("\t#{acc.join}")
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "Sysdba: #{acc.join}")
			end
		else
			print_error("\tCould not enumerate sysadmin accounts!")
			report_note(:host => datastore['RHOST'],
				:proto => 'TCP',
				:port => datastore['RPORT'],
				:type => 'MSSQL_ENUM',
				:data => "Could not enumerate sysadmin accounts")
		end

		#-------------------------------------------------------
		# Get list of Windows logins on System
		print_status("Windows Logins on this Server:")
		if vernum.join != "2000"
			winusers = mssql_query("select name from master.sys.syslogins where isntuser = 1")[:rows]
		else
			winusers = mssql_query("select name from master..syslogins where isntuser = 1")[:rows]
		end

		if winusers != nil
			winusers.each do |acc|
				print_status("\t#{acc.join}")
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "Windows Logins: #{acc.join}")
			end
		else
			print_status("\tNo Windows logins found!")
			report_note(:host => datastore['RHOST'],
				:proto => 'TCP',
				:port => datastore['RPORT'],
				:type => 'MSSQL_ENUM',
				:data => "No Windows logins found")
		end

		#-------------------------------------------------------
		# Get list of windows groups that can logins on the System
		print_status("Windows Groups that can logins on this Server:")
		if vernum.join != "2000"
			wingroups = mssql_query("select name from master.sys.syslogins where isntgroup = 1")[:rows]
		else
			wingroups = mssql_query("select name from master..syslogins where isntgroup = 1")[:rows]
		end

		if wingroups != nil
			wingroups.each do |acc|
				print_status("\t#{acc.join}")
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "Windows Groups: #{acc.join}")
			end
		else
			print_status("\tNo Windows Groups where found with permission to login to system.")
			report_note(:host => datastore['RHOST'],
				:proto => 'TCP',
				:port => datastore['RPORT'],
				:type => 'MSSQL_ENUM',
				:data => "No Windows Groups where found with permission to login to system")

		end

		#-------------------------------------------------------
		#Check for local accounts with same username as password
		sameasuser = []
		if vernum.join != "2000"
			sameasuser = mssql_query("SELECT name FROM sys.sql_logins WHERE PWDCOMPARE\(name, password_hash\) = 1")[:rows]
		else
			sameasuser = mssql_query("SELECT name FROM master.dbo.syslogins WHERE PWDCOMPARE\(name, password\) = 1")[:rows]
		end

		print_status("Accounts with Username and Password being the same:")
		if sameasuser != nil
			sameasuser.each do |up|
				print_status("\t#{up.join}")
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "Username: #{up.join} Password: #{up.join}")
			end
		else
			print_status("\tNo Account with its password being the same as its username was found.")
			report_note(:host => datastore['RHOST'],
				:proto => 'TCP',
				:port => datastore['RPORT'],
				:type => 'MSSQL_ENUM',
				:data => "No Account with its password being the same as its username was found")
		end

		#-------------------------------------------------------
		#Check for local accounts with empty password
		blankpass = []
		if vernum.join != "2000"
			blankpass = mssql_query("SELECT name FROM sys.sql_logins WHERE PWDCOMPARE\(\'\', password_hash\) = 1")[:rows]
		else
			blankpass = mssql_query("SELECT name FROM master.dbo.syslogins WHERE password IS NULL AND isntname = 0")[:rows]
		end

		print_status("Accounts with empty password:")
		if blankpass != nil
			blankpass.each do |up|
				print_status("\t#{up.join}")
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "Username: #{up.join} Password: EMPTY ")
			end
		else
			print_status("\tNo Accounts with empty passwords where found.")
			report_note(:host => datastore['RHOST'],
				:proto => 'TCP',
				:port => datastore['RPORT'],
				:type => 'MSSQL_ENUM',
				:data => "No Accounts with empty passwords where found")
		end

		#-------------------------------------------------------
		#Check for dangerous stored procedures
		fountsp = []
		dangeroussp = [
			'sp_createorphan',
			'sp_droporphans',
			'sp_getschemalock',
			'sp_prepexec',
			'sp_prepexecrpc',
			'sp_refreshview',
			'sp_releaseschemalock',
			'sp_replpostschema',
			'sp_replsendtoqueue',
			'sp_replsetsyncstatus',
			'sp_replwritetovarbin',
			'sp_resyncexecute',
			'sp_resyncexecutesql',
			'sp_resyncprepare',
			'sp_resyncuniquetable',
			'sp_unprepare',
			'sp_xml_preparedocument',
			'sp_xml_removedocument',
			'sp_fulltext_getdata',
			'sp_getbindtoken',
			'sp_replcmds',
			'sp_replcounters',
			'sp_repldone',
			'sp_replflush',
			'sp_replincrementlsn',
			'sp_replpostcmd',
			'sp_replsetoriginator',
			'sp_replstatus',
			'sp_repltrans',
			'sp_replupdateschema',
			'sp_reset_connection',
			'sp_sdidebug',
			'xp_availablemedia',
			'xp_check_query_results',
			'xp_cleanupwebtask',
			'xp_cmdshell',
			'xp_convertwebtask',
			'xp_deletemail',
			'xp_dirtree',
			'xp_displayparamstmt',
			'xp_dropwebtask',
			'xp_dsninfo',
			'xp_enum_activescriptengines',
			'xp_enum_oledb_providers',
			'xp_enumcodepages',
			'xp_enumdsn',
			'xp_enumerrorlogs',
			'xp_enumgroups',
			'xp_enumqueuedtasks',
			'xp_eventlog',
			'xp_execresultset',
			'xp_fileexist',
			'xp_findnextmsg',
			'xp_fixeddrives',
			'xp_get_mapi_default_profile',
			'xp_get_mapi_profiles',
			'xp_get_tape_devices',
			'xp_getfiledetails',
			'xp_getnetname',
			'xp_grantlogin',
			'xp_initcolvs',
			'xp_intersectbitmaps',
			'xp_logevent',
			'xp_loginconfig',
			'xp_logininfo',
			'xp_makewebtask',
			'xp_mergexpusage',
			'xp_monitorsignal',
			'xp_msver any user',
			'xp_msx_enlist',
			'xp_ntsec_enumdomains',
			'xp_ntsec_enumgroups',
			'xp_ntsec_enumusers',
			'xp_oledbinfo',
			'xp_perfend',
			'xp_perfmonitor',
			'xp_perfsample',
			'xp_perfstart',
			'xp_printstatements',
			'xp_prop_oledb_provider',
			'xp_proxiedmetadata',
			'xp_qv',
			'xp_readerrorlog',
			'xp_readmail',
			'xp_readwebtask',
			'xp_regaddmultistring',
			'xp_regdeletekey',
			'xp_regdeletevalue',
			'xp_regenumvalues',
			'xp_regread',
			'xp_regremovemultistring',
			'xp_regwrite',
			'xp_repl_encrypt',
			'xp_revokelogin',
			'xp_runwebtask',
			'xp_schedulersignal',
			'xp_sendmail',
			'xp_servicecontrol',
			'xp_showcolv',
			'xp_showlineage',
			'xp_snmp_getstate',
			'xp_snmp_raisetrap',
			'xp_sprintf any user', # huh?
			'xp_sqlagent_enum_jobs',
			'xp_sqlagent_is_starting',
			'xp_sqlagent_monitor',
			'xp_sqlagent_notify',
			'xp_sqlinventory',
			'xp_sqlmaint',
			'xp_sqlregister',
			'xp_sqltrace',
			'xp_startmail',
			'xp_stopmail',
			'xp_subdirs',
			'xp_terminate_process',
			'xp_test_mapi_profile',
			'xp_trace_addnewqueue',
			'xp_trace_deletequeuedefinition',
			'xp_trace_destroyqueue',
			'xp_trace_enumqueuedefname',
			'xp_trace_enumqueuehandles',
			'xp_trace_eventclassrequired',
			'xp_trace_flushqueryhistory',
			'xp_trace_generate_event',
			'xp_trace_getappfilter',
			'xp_trace_getconnectionidfilter',
			'xp_trace_getcpufilter',
			'xp_trace_getdbidfilter',
			'xp_trace_getdurationfilter',
			'xp_trace_geteventfilter',
			'xp_trace_geteventnames',
			'xp_trace_getevents',
			'xp_trace_gethostfilter',
			'xp_trace_gethpidfilter',
			'xp_trace_getindidfilter',
			'xp_trace_getntdmfilter',
			'xp_trace_getntnmfilter',
			'xp_trace_getobjidfilter',
			'xp_trace_getqueueautostart',
			'xp_trace_getqueuecreateinfo',
			'xp_trace_getqueuedestination',
			'xp_trace_getqueueproperties',
			'xp_trace_getreadfilter',
			'xp_trace_getserverfilter',
			'xp_trace_getseverityfilter',
			'xp_trace_getspidfilter',
			'xp_trace_getsysobjectsfilter',
			'xp_trace_gettextfilter',
			'xp_trace_getuserfilter',
			'xp_trace_getwritefilter',
			'xp_trace_loadqueuedefinition',
			'xp_trace_opentracefile',
			'xp_trace_pausequeue',
			'xp_trace_restartqueue',
			'xp_trace_savequeuedefinition',
			'xp_trace_setappfilter',
			'xp_trace_setconnectionidfilter',
			'xp_trace_setcpufilter',
			'xp_trace_setdbidfilter',
			'xp_trace_setdurationfilter',
			'xp_trace_seteventclassrequired',
			'xp_trace_seteventfilter',
			'xp_trace_sethostfilter',
			'xp_trace_sethpidfilter',
			'xp_trace_setindidfilter',
			'xp_trace_setntdmfilter',
			'xp_trace_setntnmfilter',
			'xp_trace_setobjidfilter',
			'xp_trace_setqueryhistory',
			'xp_trace_setqueueautostart',
			'xp_trace_setqueuecreateinfo',
			'xp_trace_setqueuedestination',
			'xp_trace_setreadfilter',
			'xp_trace_setserverfilter',
			'xp_trace_setseverityfilter',
			'xp_trace_setspidfilter',
			'xp_trace_setsysobjectsfilter',
			'xp_trace_settextfilter',
			'xp_trace_setuserfilter',
			'xp_trace_setwritefilter',
			'xp_trace_startconsumer',
			'xp_unc_to_drive',
			'xp_updatecolvbm',
			'xp_updateFTSSQLAccount',
			'xp_updatelineage',
			'xp_varbintohexstr',
			'xp_writesqlinfo',
			'xp_MSplatform',
			'xp_MSnt2000',
			'xp_MSLocalSystem',
			'xp_IsNTAdmin',
			'xp_mapdown_bitmap'
		]

		query = <<-EOS
SELECT CAST(SYSOBJECTS.NAME AS CHAR) FROM SYSOBJECTS, SYSPROTECTS WHERE SYSPROTECTS.UID = 0 AND XTYPE IN ('X','P')
AND SYSOBJECTS.ID = SYSPROTECTS.ID
EOS
		fountsp = mssql_query(query)[:rows]
		if fountsp != nil
			fountsp.flatten!
			print_status("Stored Procedures with Public Execute Permission found:")
			fountsp.each do |strp|
				if dangeroussp.include?(strp.strip)
					print_status("\t#{strp.strip}")
					report_note(:host => datastore['RHOST'],
						:proto => 'TCP',
						:port => datastore['RPORT'],
						:type => 'MSSQL_ENUM',
						:data => "Stored Procedures with Public Execute Permission #{strp.strip}")
				end
			end
		else
			print_status("\tNo Dangerous Stored Procedure found with Public Execute.")
			report_note(:host => datastore['RHOST'],
				:proto => 'TCP',
				:port => datastore['RPORT'],
				:type => 'MSSQL_ENUM',
				:data => "No Dangerous Stored Procedure found with Public Execute")
		end

		#-------------------------------------------------------
		#Enumerate Instances
		instances =[]
		if vernum.join != "2000"
			querykey = "EXEC master..xp_regenumvalues \'HKEY_LOCAL_MACHINE\',\'SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL\'"
			instance_res = mssql_query(querykey)[:rows]
			if instance_res != nil
				instance_res.each do |i|
					instances << i[0]
				end
			end
		else
			querykey = "exec xp_regread \'HKEY_LOCAL_MACHINE\',\'SOFTWARE\\Microsoft\\Microsoft SQL Server\', \'InstalledInstances\'"
			instance_res = mssql_query(querykey)[:rows]
			if instance_res != nil
				instance_res.each do |i|
					instances << i[1]
				end
			end
		end

		print_status("Instances found on this server:")
		instancenames = []
		if instances != nil
			instances.each do |i|
				print_status("\t#{i}")
				instancenames << i.strip
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "Instance Name: #{i}")
			end
		else
			print_status("No instances found, possible permission problem")
		end

		#---------------------------------------------------------
		#Enumerate under what accounts the instance services are running under
		print_status("Default Server Instance SQL Server Service is running under the privilege of:")
		privdflt = mssql_query("EXEC master..xp_regread \'HKEY_LOCAL_MACHINE\' ,\'SYSTEM\\CurrentControlSet\\Services\\MSSQLSERVER\',\'ObjectName\'")[:rows]
		if privdflt != nil
			privdflt.each do |priv|
				print_status("\t#{priv[1]}")
				report_note(:host => datastore['RHOST'],
					:proto => 'TCP',
					:port => datastore['RPORT'],
					:type => 'MSSQL_ENUM',
					:data => "Default Instance SQL Server running as: #{priv[1]}")
			end
		else
			print_status("\txp_regread might be disabled in this system")
		end

		#------------------------------------------------------------
		if instancenames.length > 1
			instancenames.each do |i|
				if i.strip != "MSSQLSERVER"
					privinst = mssql_query("EXEC master..xp_regread \'HKEY_LOCAL_MACHINE\' ,\'SYSTEM\\CurrentControlSet\\Services\\MSSQL$#{i.strip}\',\'ObjectName\'")[:rows]
					if privinst != nil
						print_status("Instance #{i} SQL Server Service is running under the privilege of:")
						privinst.each do |p|
							print_status("\t#{p[1]}")
							report_note(:host => datastore['RHOST'],
								:proto => 'TCP',
								:port => datastore['RPORT'],
								:type => 'MSSQL_ENUM',
								:data => "#{i} Instance SQL Server running as: #{p[1]}")
						end
					else
						print_status("\tCould not enumerate credentials for Instance.")
					end
				end
			end
		end

		disconnect
	end
end
