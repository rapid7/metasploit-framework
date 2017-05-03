##
#
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows/registry'


class Metasploit3 < Msf::Post
	include Msf::Post::Common
	include Msf::Post::Windows::Registry	


	def initialize(info={})
		super(update_info(info,
			'Name'           => "Windows Gather list security updates not applied for local vulnerabilities on windows OS",
			'Description'    => %q{
					This module will give status of security patches for local privilege vulnerabilities on various
					windows OS. It will first check privilege and continue only if you are not having System or
					Administrator privilege. Finally it gives you list of security patches that are applied and
					patches that are not applied to Windows OS. It basically does this by comparing patches applied
					to windows OS with list of local vulnerabilities published by Microsoft on there website for
					respective windows OS. The modules also tries to indicates if there are exploits avaliable for
					vulnerabilities which will help you to escalate privileges.
					},
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 13804 $',
			'Platform'       => ['windows'],
			'SessionTypes'   => ['meterpreter'],
			'Author'         => ['Harshal Chaudhari <samurai_h21[at]yahoo.com>']
		))
	end



	def run

	########### Function to get KB list from Kblist.txt file located under 'data' folder ###############
	def get_kblist(srhstring)
	found = false
	list = Array.new()
	
		begin
		path = ::File.join(Msf::Config.install_root, "data", "Kblist.txt")
		file = ::File.open(path, "r")	

		file.each{|line|
			found = false if (line =~ /^#{srhstring}_stop/)
			list << line.chomp  if(found)
			found = true  if (line =~ /^#{srhstring}_start/)
		}
			return list
			f.close
		rescue
			print_error("Error reading file #{path}")
			return nil
		end
	
	
	end



	################ Function:: To check for OSversion, Edition, Service pack and pick corresponding KB list ######################
	def chk_os_sp (edition)
	
	
		inkb= nil
		ver = client.sys.config.sysinfo
		os_sp = ver['OS']
		arch = ver['Architecture']
	
		if arch =~ /x86/
		print_status ("\t Architecture :- #{arch} ")
		print_status("\t OS version :- #{ver['OS']}")
	
			if  os_sp =~ /(Windows 2000)/
				cmdis = "reg"
	
				if edition =~ /Advance/
					if os_sp =~ /(Service Pack 1)/
						sstr = 't2k_sp1_kb'
						inkb = get_kblist(sstr)
					elsif os_sp =~ /(Service Pack 2)/
						sstr = 't2k_sp2_kb'
						inkb = get_kblist(sstr)
					elsif os_sp =~ /(Service Pack 3)/
						sstr = 't2k_sp3_kb'
						inkb = get_kblist(sstr)
					elsif os_sp =~ /(Service Pack 4)/
						sstr = 't2kadv_sp4_kb'
						inkb = get_kblist(sstr)
					elsif os_sp !=~ /(Service Pack)/ #no service pack
						print_status("\t No local privilege vulnerability for win 2000 with no service pack")
					end
				elsif edition =~ /Professional/
					if os_sp =~ /(Service Pack 1)/
						sstr = 't2k_sp1_kb'
						inkb = get_kblist(sstr)
					elsif os_sp =~ /(Service Pack 2)/
						sstr = 't2k_sp2_kb'
						inkb = get_kblist(sstr)
					elsif os_sp =~ /(Service Pack 3)/
						sstr = 't2kpro_sp3_kb'
						inkb = get_kblist(sstr)
					elsif os_sp =~ /(Service Pack 4)/
						sstr = 't2k_sp4_kb'
						inkb = get_kblist(sstr)
					elsif os_sp !=~ /(Service Pack)/  # no servicepack	
						print_status("\t No local privilege vulnerability for win 2000 with no service pack")
					end
				else
					if os_sp =~ /(Service Pack 1)/
						sstr = 't2k_sp1_kb'
						inkb = get_kblist(sstr)
					elsif os_sp =~ /(Service Pack 2)/
						sstr = 't2k_sp2_kb'
						inkb = get_kblist(sstr)
					elsif os_sp =~ /(Service Pack 3)/
						sstr = 't2k_sp3_kb'
						inkb = get_kblist(sstr)
					elsif os_sp =~ /(Service Pack 4)/
						sstr = 't2k_sp4_kb'
						inkb = get_kblist(sstr)
					elsif os_sp !=~ /(Service Pack)/ # no servicepack	
						print_status("\t No local privilege vulnerability for win 2000 with no service pack")
					end
				end
	
			elsif  os_sp =~ /(Windows XP)/
				cmdis = "reg"
	
				if edition =~ /Home/
				print_status("\t Edition: Home")
					if os_sp =~ /(Service Pack 1)/
						sstr = 'xphm_sp1_kb'
						inkb = get_kblist(sstr)
					elsif os_sp =~ /(Service Pack 2)/
						sstr = 'xphm_sp2_kb'
						inkb = get_kblist(sstr)
					elsif os_sp =~ /(Service Pack 3)/
						sstr = 'xphm_sp3_kb'
						inkb = get_kblist(sstr)
					elsif os_sp !=~ /(Service Pack)/  #no service pack
						sstr = 'xphm_nosp_kb'
						inkb = get_kblist(sstr)
					end
				elsif edition =~ /Professional/
				print_status("\t Edition: Professional")
					if os_sp =~ /(Service Pack 1)/
						sstr = 'xppro_sp1_kb'
						inkb = get_kblist(sstr)
					elsif os_sp =~ /(Service Pack 2)/
						sstr = 'xppro_sp2_kb'
						inkb = get_kblist(sstr)
					elsif os_sp =~ /(Service Pack 3)/
						sstr = 'xppro_sp3_kb'
						inkb = get_kblist(sstr)
					elsif os_sp !=~ /(Service Pack)/  # no servicepack	
						sstr = 'xppro_nosp_kb'
						inkb = get_kblist(sstr)
					end
				end
	
			elsif os_sp =~ /(Windows .NET Server)/
				cmdis = "reg"
	
				if edition !=~ /Small Business/
					if os_sp =~ /(Service Pack 1)/
						sstr = 'w2k3_sp1_kb'
						inkb = get_kblist(sstr)
					elsif os_sp =~ /(Service Pack 2)/
						sstr = 'w2k3_sp2_kb'
						inkb = get_kblist(sstr)
					elsif os_sp !=~ /(Service Pack)/
						sstr = 'w2k3_nosp_kb'
						inkb = get_kblist(sstr)
					end
				end
	
			elsif os_sp =~ /(Windows 2008)/
				cmdis = nil
	
					if os_sp !=~ /(Service Pack)/
						sstr = 'w2k8_nosp_kb'
						inkb = get_kblist(sstr)
					elsif os_sp =~ /(Service Pack 2)/
						sstr = 'w2k8_sp2_kb'
						inkb = get_kblist(sstr)
					end
	
			elsif os_sp =~ /(Windows Vista)/
				cmdis = nil
	
					if os_sp =~ /(Service Pack 1)/
						sstr = 'vs_sp1_kb'
						inkb = get_kblist(sstr)
					elsif os_sp =~ /(Service Pack 2)/
						sstr = 'vs_sp2_kb'
						inkb = get_kblist(sstr)
					elsif os_sp !=~ /(Service Pack)/  #no service pack
						sstr = 'vs_nosp_kb'
						inkb = get_kblist(sstr)
					end
	
			elsif os_sp =~ /(Windows 7)/
				cmdis = nil

					if os_sp =~ /(Service Pack 1)/
						sstr = 'w7_sp1_kb'
						inkb = get_kblist(sstr)
					elsif os_sp !=~ /(Service Pack)/  #no service pack
						sstr = 'w7_nosp_kb'
						inkb = get_kblist(sstr)
					end
	
			else
			print_status("\t You are running the script on non-supported OS")	
			end
	
		if inkb != nil
		return inkb,cmdis
		end
	
	##########------------ 64 arch -------------##################
		elsif arch =~ /x64/
		print_status ("\t Architecture:- #{arch} ")
		print_status("\t OS version :- #{ver['OS']}")
	
			if os_sp =~ /(Windows 7)/
			cmdis = nil
	
					if os_sp =~ /(Service Pack 1)/
						sstr = 'w7_64_sp1_kb'
						inkb = get_kblist(sstr)
					elsif os_sp !=~ /(Service Pack)/ #no service pack
						sstr = 'w7_64_nosp_kb'
						inkb = get_kblist(sstr)
					end
	
			elsif os_sp =~ /(Windows XP)/
				cmdis = "reg"
				if edition =~ /Professional/
					if os_sp =~ /(Service Pack 2)/
						sstr = 'xppro_64_sp2_kb'
						inkb = get_kblist(sstr)
					elsif os_sp !=~ /(Service Pack)/  #no service pack
						sstr = 'xppro_64_nosp_kb'
						inkb = get_kblist(sstr)
					end
				end
	
			elsif os_sp =~ /(Windows Vista)/
			cmdis = nil

					if os_sp =~ /(Service Pack 1)/
						sstr = 'vs_64sp1_kb'
						inkb = get_kblist(sstr)
					elsif os_sp =~ /(Service Pack 2)/
						sstr = 'vs_64sp2_kb'
						inkb = get_kblist(sstr)
					elsif os_sp !=~ /(Service Pack)/  #no service pack
						sstr = 'vs_64nosp_kb'
						inkb = get_kblist(sstr)
					end
	
			elsif os_sp =~ /(windows 2008)/
			cmdis = nil 
	
				if edition =~ /2008 R2/
				print_status("\t Edition: Windows server 2008 R2")
					if os_sp =~ /(Service Pack 1)/
						sstr = 'w2k8_64r2_sp1_kb'
						inkb = get_kblist(sstr)
					elsif os_sp !=~ /(Service Pack)/
						sstr = 'w2k8_64r2_kb'
						inkb = get_kblist(sstr)
					end
				else
					if os_sp !=~ /(Service Pack)/
						sstr = 'w2k8_64nosp_kb'
						inkb = get_kblist(sstr)
					elsif os_sp =~ /(Service Pack 2)/
						sstr = 'w2k8_64sp2_kb'
						inkb = get_kblist(sstr)
					end
				end
	
			elsif os_sp =~ /(windows .NET Server)/
				cmdis = "reg"
	
				if edition =~ /Datacenter/
				print_status("\t Edition: Windows server 2003 Datacenter")
					if os_sp =~ /(Service Pack 2)/
						sstr = 'w2k3_64_sp2_kb'
						inkb = get_kblist(sstr)
					elsif os_sp !=~ /(Service Pack)/
						sstr = 'w2k3_64dc_nosp_kb'
						inkb = get_kblist(sstr)
					end
	
				elsif edition=~ /Enterprise/
					print_status("\t Edition: Windows server 2003 Enterprise")
					if os_sp =~ /(Service Pack 2)/
						sstr = 'w2k3_64ent_sp2_kb'
						inkb = get_kblist(sstr)
					elsif os_sp !=~ /(Service Pack)/
						sstr = 'w2k3_64ent_nosp_kb'
						inkb = get_kblist(sstr)
					end
	
				elsif edition=~ /Standard/
				print_status("\t Edition: Windows server 2003 Standard")
					if os_sp =~ /(Service Pack 2)/
						sstr = 'w2k3_64_sp2_kb'
						inkb = get_kblist(sstr)
					elsif os_sp !=~ /(Service Pack)/
						sstr = 'w2k3_64std_nosp_kb'
						inkb = get_kblist(sstr)
					end
				end
	
			else
			print_status("\t You are running the script on non-supported OS")
			end
	
		if inkb != nil
			return inkb,cmdis
		end
	
		elsif arch =~ /IA64/
			print_status("\t You are running the script on non-supported IA64 CPU Architecture")
		end
	
	
	end
	
	
	
	####################################
	############    Main   #############
	
	
	print_status("Listing status for local privilege vulnerability patches on Windows OS")
	
	#
	# Check if you are already Admin OR System 
	#
	
	adminbuff= nil
	username  = client.sys.config.getuid
	p1,p2 = username.split("\\")
	
	print_status("Checking if you are already Administrator or System...")
	adminbuff =  cmd_exec("net", "localgroup administrators")

			print_status("\t --------------------------------------------------")

	if /#{p2}/ == /SYSTEM/
			print_status("\t Aborting because you are already with System privilege")
	
	elsif adminbuff =~ /#{p2}/ 
			print_status("\t Aborting because you are already Administrator #{p2}")
	else
			print_status("\t You are NOT having Administrator privilege:- #{p2}")
	
			tmp = cmd_exec("systeminfo")
	
				if tmp =~ /XP Home/	
					inedition = "Home"
				elsif tmp =~ /Professional/
					if tmp =~ /XP Professional/	
						if tmp =~ /2003/	
						inedition = nil
						else
						inedition = "Professional"
						end
					else
						inedition = "Professional"
					end
				elsif tmp =~ /Advance/
					inedition = "Advance"
				elsif tmp =~ /2008 R2/
					inedition = "2008 R2"
				elsif tmp =~ /Small Business/
					inedition = "Small Business"
				elsif tmp =~ /Datacenter/
					inedition = "Datacenter"
				elsif tmp =~ /Enterprise/
					inedition = "Enterprise"
				elsif tmp =~ /Standard/
					inedition = "Standard"
				else
					inedition = nil
				end
	
		kblist, cmd = chk_os_sp(inedition)
			if cmd =~ /reg/
			kbbuff = cmd_exec("reg", "query HKLM\\software\\microsoft\\windows\\currentversion\\uninstall")
 			updatebuff = cmd_exec("reg", "query HKLM\\software\\microsoft\\updates /s")	
				kbbuff = kbbuff << updatebuff
			else
			kbbuff = tmp
			end

			## Check if IIS is installed
			sc1buff = cmd_exec("reg", "query HKLM\\SYSTEM\\CurrentControlSet\\Services\\IISAdmin /s")
			chkiis = 0
			iis_acc = 0
			if sc1buff =~ /IISAdmin/
				chkiis = 1
				if sc1buff =~ /NetworkService|LocalSystem/
					iis_acc = 1
				end
			end

			## Check if DNS is installed
			sc2buff = cmd_exec("sc", "query dns")
			chkdns = 0
			if sc2buff =~ /dns/
				chkdns = 1
			end

			## Check if MSMQ is installed
			sc3buff = cmd_exec("reg", "query HKLM\\SYSTEM\\CurrentControlSet\\Services\\MSMQ")
			chkmsmq = 0
			if sc3buff =~ /msmq/
				chkmsmq = 1
			end

			## Check if rdp on IIS is installed
			rdpbuff = cmd_exec("cmd.exe", "/c dir c:\\windows\\web\\tsweb")
			chkrdp = 0
			if rdpbuff =~ /msrdp.cab/
				chkrdp = 1
			end
 
			## Check if AD is installed
			adbuff = cmd_exec("net accounts")
			chkad = 0
			if adbuff =~ /PRIMARY|SECONDARY/
				chkad = 1
			end

			## Check if ADAM or AD LDS is installed
			adamlsbuff = cmd_exec("reg", "query HKLM\\software\\microsoft\\windows\\currentversion\\adam_shared /s")
			chkadamls = 0
			if adamlsbuff =~ /adaminstall.exe/
				chkadamls = 1
			end

			## Check if IME Korean is installed
			imekrbuff = cmd_exec("reg", "query HKLM\\software\\microsoft\\IMEKR /s")
			chkimekr = 0
			if imekrbuff =~ /IME\\IMKR|IME\\IMEKR/
				chkimekr = 1
			end

			## Check if Services for Unix is installed 
			sfubuff = registry_getvaldata("HKLM\\software\\microsoft\\services for unix","current_release")
			chksfu = 0
			if sfubuff =~ /3.0|3.5/
				chksfu = 1
			end

			## Check if Windows sharepoint service3 or MS office sharepoint server 2007 is installed 
			moss2k7buff = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\Office Server\\12.0","buildversion")
			chkmoss2k7 = 0
			if moss2k7buff =~ /12\.0\.6036|12\.0\.4518/
				chkmoss2k7 = 1
			end
			wss3buff = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\Shared Tools\\Web Server Extensions\\12.0","version")
			chkwss3 = 0
			if wss3buff =~ /12\.0\.0\.6036|12\.0\.0\.4518/
				chkwss3 = 1
			end
			chkwssmoss = 0
			if chkwss3 == 1 or chkmoss2k7 == 1
				chkwssmoss = 1
			end

			## Check if MS SQL 2000 or 2005 is installed
			mssql2k_2k5buff = registry_getvaldata("HKLM\\software\\microsoft\\microsoft sql server\\90\\tools\\clientsetup\\currentversion","currentversion")
			chkmssql2k_2k5 = 0
			chkmssql2k_2k5 = 1 if (mssql2k_2k5buff =~ /8\.00\.194/)
			chkmssql2k_2k5 = 1 if (mssql2k_2k5buff =~ /8\.00\.384/)
			chkmssql2k_2k5 = 1 if (mssql2k_2k5buff =~ /8\.00\.534/)
			chkmssql2k_2k5 = 1 if (mssql2k_2k5buff =~ /8\.00\.760/)
			chkmssql2k_2k5 = 1 if (mssql2k_2k5buff =~ /8\.00\.2039/)
			chkmssql2k_2k5 = 1 if (mssql2k_2k5buff =~ /9\.00\.1399\.06/)
			chkmssql2k_2k5 = 1 if (mssql2k_2k5buff =~ /9\.00\.2047\.00/)
			chkmssql2k_2k5 = 1 if (mssql2k_2k5buff =~ /9\.00\.3042\.00/)

			## Check account under which MS SQL service is running
			mssqlbuff = registry_getvaldata("HKLM\\system\\currentcontrolset\\services\\mssqlserver","objectname")
			mssqlexp  = registry_getvaldata("HKLM\\system\\currentcontrolset\\services\\mssql$sqlexpress","objectname")
			mssql_acc = 0
			if (mssqlbuff =~ /NetworkService|LocalSystem/) or (mssqlexp =~ /NetworkService|LocalSystem/)
				mssql_acc = 1
			end
			iis_sql_acc = 0
			if (iis_acc == 1) or (mssql_acc == 1)
				iis_sql_acc = 1
			end


			## Check if Certificate service is installed
			crtsrvbuff = cmd_exec("reg", "query HKLM\\System\\CurrentControlSet\\Services\\CertSvc\\")
			chkcrtsrv = 0
			if crtsrvbuff =~ /certsrv.exe/
				chkcrtsrv = 1
			end


			fpath = ::File.join(Msf::Config.install_root, "data", "Kblist.txt")
			print_status("\t Reading KB list from #{fpath}")
			print_status("\t --------------------------------------------------")

			allkblist = Array.new()
			     sstr = "allkblist"
		        allkblist = get_kblist(sstr)

			if kblist != nil
				if kbbuff =~ /uninstall|OS Name|updates/

					kblist.each do |kb|

						if kbbuff =~ /#{kb}/
							print_status("\t Patch installed for #{kb}")
						else
							## be silent.. and skip this kb if respective services are not installed 
							if    kb == '970483'  and chkiis == 0
							elsif kb == '942831'  and chkiis == 0
							elsif kb == '2562485' and chkdns == 0
							elsif kb == '2546250' and chkiis == 0 and chkrdp == 0
							elsif kb == '901190'  and chkimekr == 0
							elsif kb == '939778'  and chksfu == 0
							elsif kb == '971032'  and chkmsmq == 0
							elsif kb == '981550'  and chkadamls == 0
							elsif kb == '2616310' and chkadamls == 0
							elsif kb == '2601626' and chkad == 0
							elsif kb == '2518295' and chkcrtsrv == 0
							elsif kb == '959420'  and chkmssql2k_2k5 == 0
							elsif kb == '942017'  and chkwssmoss == 0
							elsif kb == '952004'  and iis_sql_acc == 0
							elsif kb == '956572'  and iis_sql_acc == 0
							elsif kb == '982799'  and iis_sql_acc == 0
							else
								
								allkblist.each do |onekb|
									if onekb =~ /#{kb}/
									print_status("\t No patch installed for #{onekb}")
									end
								end
							end
						end
					end
				end
			end
	
	end


	end

end
