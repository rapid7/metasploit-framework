import msf.*;
import java.awt.*;
import java.io.*;
import java.net.*;
import javax.swing.*;
import javax.imageio.*;
import ui.*;

sub host_selected_items {
	local('$sid $session $i $s $h $o');

	host_attack_items($1, $2);

	setupMenu($1, "host_top", $2);

	if ($2[0] in %hosts && 'sessions' in %hosts[$2[0]]) {
		foreach $sid => $session (%hosts[$2[0]]['sessions']) {
			if ($session["type"] eq "meterpreter") {
				$i = menu($1, "Meterpreter $sid", $sid);
				showMeterpreterMenu($i, \$session, \$sid);
			}
			else if ($session["type"] eq "shell") {
				$i = menu($1, "Shell $sid", $sid);
				showShellMenu($i, \$session, \$sid);
			}
		}
	}

	item($1, "Services", 'v', lambda({ createServiceBrowser($hosts) }, $hosts => $2));
	item($1, "Scan", 'c', lambda({ launch_msf_scans(join(", ", $hosts)); }, $hosts => $2));

	setupMenu($1, "host_bottom", $2);

	separator($1);

	$h = menu($1, "Host", 'H');

		$o = menu($h, "Operating System", 'O');
		item($o, "Android", 'A', setHostValueFunction($2, "os_name", "Android"));
		item($o, "Apple iOS", 'i', setHostValueFunction($2, "os_name", "Apple iOS"));
		item($o, "Cisco IOS", 'C', setHostValueFunction($2, "os_name", "Cisco IOS"));
		item($o, "FreeBSD", 'F', setHostValueFunction($2, "os_name", "FreeBSD"));
		item($o, "Linux", 'L', setHostValueFunction($2, "os_name", "Linux"));
		item($o, "NetBSD", 'N', setHostValueFunction($2, "os_name", "NetBSD"));
		item($o, "Mac OS X", 'M', setHostValueFunction($2, "os_name", "Apple Mac OS X"));
		item($o, "OpenBSD", 'O', setHostValueFunction($2, "os_name", "OpenBSD"));
		item($o, "Printer", 'P', setHostValueFunction($2, "os_name", "Printer"));
		item($o, "Solaris", 'S', setHostValueFunction($2, "os_name", "Solaris"));
		item($o, "Unknown", 'U', setHostValueFunction($2, "os_name", ""));
		item($o, "VMware", 'V', setHostValueFunction($2, "os_name", "VMware"));
		$i = menu($o, "Windows", 'W');
			item($i, '1. 95/98/2000', '1', setHostValueFunction($2, "os_name", "Micosoft Windows", "os_flavor", "2000"));
			item($i, '2. XP/2003', '2', setHostValueFunction($2, "os_name", "Microsoft Windows", "os_flavor", "XP"));
			item($i, '3. Vista/7', '3', setHostValueFunction($2, "os_name", "Microsoft Windows", "os_flavor", "Vista"));
			item($i, '4. 8/RT', '4', setHostValueFunction($2, "os_name", "Microsoft Windows", "os_flavor", "8"));

		item($h, "Remove Host", 'R', clearHostFunction($2));
}

sub view_items {
	# make it so we can recreate this menu if necessary...
	setf('&recreate_view_items', lambda({ [$parent removeAll]; view_items($parent); }, $parent => $1));

	item($1, 'Console', 'C', { thread(&createConsoleTab); });
	
	if ($mclient !is $client && $mclient !is $null) {
		item($1, 'Event Log', 'E', &createEventLogTab);
	}

	setupMenu($1, "view_top", @());

	separator($1);

	item($1, 'Credentials', 'r', { thread(&createCredentialsTab); });
	item($1, 'Downloads', 'D', { thread(&createDownloadBrowser); });
	item($1, 'Jobs', 'J', { thread(&createJobsTab); });
	item($1, 'Loot', 'L', { thread(&createLootBrowser) });
	item($1, 'Script Console', 'S', { showScriptConsole(); });

	setupMenu($1, "view_middle", @());

	separator($1);

	local('$t');
	$t = menu($1, 'Reporting', 'R');

	item($t, 'Activity Logs', 'A', gotoFile([new File: dataDirectory()]));
	item($t, 'Export Data', 'E', {
		thread(&generateArtifacts);
	});

	setupMenu($1, "view_bottom", @());

}

sub armitage_items {
	local('$m');

	item($1, 'Preferences', 'P', &createPreferencesTab);

	separator($1);

	dynmenu($1, 'Set Target View', 'S', {
		local('$t1 $t2');
		if ([$preferences getProperty: "armitage.string.target_view", "graph"] eq "graph") {
			$t1 = 'Graph View *';
			$t2 = 'Table View';
		}
		else {
			$t1 = 'Graph View';
			$t2 = 'Table View *';
		}
	
		item($1, $t1, 'G', {
			[$preferences setProperty: "armitage.string.target_view", "graph"];
			createDashboard();
			savePreferences();
		});

		item($1, $t2, 'T', {
			[$preferences setProperty: "armitage.string.target_view", "table"];
			createDashboard();
			savePreferences();
		});
	});

	dynmenu($1, 'Set Exploit Rank', 'E', {
		local('$f @ranks $rank');
		$f = {
			[$preferences setProperty: "armitage.required_exploit_rank.string", $rank];
			savePreferences();
			showError("Updated minimum exploit rank.");
		};

		@ranks = @("Excellent", "Great", "Good", "Normal", "Poor");

		foreach $rank (@ranks) {
			if ([$preferences getProperty: "armitage.required_exploit_rank.string", "great"] eq lc($rank)) {
				item($1, "$rank *", charAt($rank, 0), lambda($f, $rank => lc($rank)));
			}
			else {
				item($1, $rank, charAt($rank, 0), lambda($f, $rank => lc($rank)));
			}
		}
	});

	setupMenu($1, "main_top", @());

	separator($1);

	item($1, 'SOCKS Proxy...', 'r', &manage_proxy_server);

	$m = menu($1, 'Listeners', 'L');
		item($m, 'Bind (connect to)', 'B', &connect_for_shellz);
		item($m, 'Reverse (wait for)', 'R', &listen_for_shellz); 

	item($1, 'Scripts...', 'S', { showScriptManager(); });

	setupMenu($1, "main_middle", @());

	separator($1);

	item($1, 'Exit', 'x', { 
		if ($msfrpc_handle !is $null) {
			closef($msfrpc_handle);
		}

		[System exit: 0]; 
	});

}

sub main_attack_items {
	local('$k');
	item($1, "Find Attacks", 'A', {
		thread({
			findAttacks("p", min_rank());
		});
	});

	item($1, "Hail Mary", 'H', {
		thread({
			smarter_autopwn("p", min_rank()); 
		});
	});

	setupMenu($1, "attacks", @());
}

sub gotoURL {
	return lambda({ 
		if ([Desktop isDesktopSupported]) {
			[[Desktop getDesktop] browse: $url];
		}
		else {
			ask("Browse to this URL:", $url);
		}
	}, $url => [[new URL: $1] toURI]);
}

sub help_items {
	item($1, "Homepage", 'H', gotoURL("http://www.fastandeasyhacking.com/")); 
	item($1, "Tutorial", 'T', gotoURL("http://www.fastandeasyhacking.com/manual"));
	item($1, "Scripts", 'S', gotoURL("https://github.com/rsmudge/cortana-scripts"));
	item($1, "Issue Tracker", 'I', gotoURL("http://code.google.com/p/armitage/issues/list")); 
	item($1, "User Survey", 'U', gotoURL("https://docs.google.com/spreadsheet/viewform?formkey=dEdSNGdJY2Z1LVloWXBnX2o4SkdGZHc6MQ"));
	setupMenu($1, "help", @());
	separator($1);
	item($1, "About", 'A', {
		local('$dialog $handle $label');
		$dialog = dialog("About", 320, 200);
		[$dialog setLayout: [new BorderLayout]];
		
		$label = [new JLabel: [new ImageIcon: [ImageIO read: resource("resources/armitage-logo.gif")]]];

		[$label setBackground: [Color black]];
		[$label setForeground: [Color gray]];
		[$label setOpaque: 1];

		$handle = [SleepUtils getIOHandle: resource("resources/about.html"), $null]; 
		[$label setText: readb($handle, -1)];
		closef($handle);
		
		[$dialog add: $label, [BorderLayout CENTER]];
		[$dialog pack];
		[$dialog setLocationRelativeTo: $null];
		[$dialog setVisible: 1];
	});
}

sub init_menus {
	local('$top');
	$top = [$1 getJMenuBar];

	dynmenu($top, "$TITLE", charAt($TITLE, 0), &armitage_items);
	dynmenu($top, "View", 'V', &view_items);
	dynmenu($top, "Hosts", 'H', &host_items);
	dynmenu($top, "Attacks", 'A', &main_attack_items);
	dynmenu($top, "Workspaces", 'W', &client_workspace_items);
	dynmenu($top, "Help", 'H', &help_items);

	# setup some global keyboard shortcuts...
	[$frame bindKey: "Ctrl+I", { 
		thread({
			chooseSession($null, $null, $null, {
				local('$session');
				$session = sessionData($1);
				if ($session is $null) {
					showError("Session $1 does not exist");
				}
				else if ($session['desc'] eq "Meterpreter") {
					createMeterpreterTab($1);
				}
				else {
					createShellSessionTab(\$session, $sid => $1);
				}
			});
		});
	}];
	[$frame bindKey: "Ctrl+N", { thread(&createConsoleTab); }];
	[$frame bindKey: "Ctrl+W", { [$frame openActiveTab]; }];
	[$frame bindKey: "Ctrl+D", { [$frame closeActiveTab]; }];
	[$frame bindKey: "Ctrl+O", { thread(&createPreferencesTab); }];
	[$frame bindKey: "Ctrl+T", { [$frame snapActiveTab]; }];
	[$frame bindKey: "Ctrl+Left", { [$frame previousTab]; }];
	[$frame bindKey: "Ctrl+Right", { [$frame nextTab]; }];
	setupWorkspaceShortcuts(workspaces());

	cmd_safe("show exploits", {
		local('$line $os $type $id $rank $name $k $date $exploit');

		foreach $line (split("\n", $3)) {
			local('@ranks');
			@ranks = @('normal', 'good', 'great', 'excellent');
			while (size(@ranks) > 0 && @ranks[0] ne min_rank()) {
				@ranks = sublist(@ranks, 1);
			}

			if ($line ismatch '\s+((.*?)\/.*?\/.*?)\s+(\d\d\d\d-\d\d-\d\d)\s+(' . join('|', @ranks) . ')\s+(.*?)') {
				($exploit, $os, $date, $rank, $name) = matched();
				%exploits[$exploit] = %(
					name => $name,
					os => $os,
					date => parseDate('yyyy-MM-dd', $date),
					rank => $rank,
					rankScore => rankScore($rank)
				);
			}
		}
		warn("Remote Exploits Synced");
	});
}
