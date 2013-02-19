import msf.*;

import javax.swing.*;
import javax.swing.event.*;

import java.awt.*;
import java.awt.event.*;

sub addHostDialog {
	local('$dialog $label $text $finish $button');
	$dialog = [new JDialog: $__frame__, "Add Hosts", 0];
	[$dialog setSize: 320, 240];
	[$dialog setLayout: [new BorderLayout]];
	[$dialog setLocationRelativeTo: $__frame__];

	$label = [new JLabel: "Enter one host/line:"];
	$text = [new JTextArea];

	$finish = [new JPanel];
	[$finish setLayout: [new FlowLayout: [FlowLayout CENTER]]];

	$button = [new JButton: "Add"];
	[$finish add: $button];

	[$button addActionListener: lambda({
		local('@hosts');
		@hosts = split("[\n\s]", [$text getText]);
		cmd_safe("hosts -a " . join(" ", @hosts), lambda({
			showError("Added $x host" . iff($x != 1, "s"));
			elog("added $x host" . iff($x != 1, "s"));
		}, $x => size(@hosts)));
		[$dialog setVisible: 0];
	}, \$text, \$dialog)];

	[$dialog add: $label, [BorderLayout NORTH]];
	[$dialog add: [new JScrollPane: $text], [BorderLayout CENTER]];
	[$dialog add: $finish, [BorderLayout SOUTH]];

	[$dialog setVisible: 1];
}

sub host_items {
	local('$i $j $k');
	item($1, "Import Hosts", 'I', &importHosts);
	item($1, "Add Hosts...", 'A', &addHostDialog);
	setupMenu($1, "hosts_top", @());

	separator($1);

	$j = menu($1, "Nmap Scan", 'S');
		setupMenu($j, "hosts_nmap", @());
		item($j, "Intense Scan", $null, createNmapFunction("--min-hostgroup 96 -T4 -A -v -n"));
		item($j, "Intense Scan + UDP", $null, createNmapFunction("--min-hostgroup 96 -sS -n -sU -T4 -A -v"));
		item($j, "Intense Scan, all TCP ports", $null, createNmapFunction("--min-hostgroup 96 -p 1-65535 -n -T4 -A -v"));
		item($j, "Intense Scan, no ping", $null, createNmapFunction("--min-hostgroup 96 -T4 -n -A -v -Pn"));
		item($j, "Ping Scan", $null, createNmapFunction("--min-hostgroup 96 -T4 -n -sn"));
		item($j, "Quick Scan", $null, createNmapFunction("--min-hostgroup 96 -T4 -n -F"));
		item($j, "Quick Scan (OS detect)", $null, createNmapFunction("--min-hostgroup 96 -sV -n -T4 -O -F --version-light"));
		item($j, "Comprehensive", $null, createNmapFunction("--min-hostgroup 96 -sS -n -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53"));

	item($1, "MSF Scans...", "M", {
		local('$address');
		$address = ask("Enter scan range (e.g., 192.168.1.0/24):", join(", ", [$targets getSelectedHosts]));
		if ($address eq "") { return; }
		launch_msf_scans($address);
	});

	item($1, "DNS Enumerate", 'D', {
		if (size([$targets getSelectedHosts]) > 0) {
			launch_dialog("Enumerate DNS", "auxiliary", "gather/enum_dns", 1, $null, %(NS => [$targets getSelectedHosts][0]));
		}
		else {
			launch_dialog("Enumerate DNS", "auxiliary", "gather/enum_dns", 1, $null, %());
		}
	});

	setupMenu($1, "hosts_middle", @());
	separator($1);
	setupMenu($1, "hosts_bottom", @());
	item($1, "Clear Database", 'C', &clearDatabase);
}

# oh yay, Metasploit now normalizes OS info (so I don't have to). Except the new constants
# they use are different than the ones they have used... *sigh* time to future proof my code.
sub normalize {
	if ("*Windows*" iswm $1) {
		return "Windows";
	}
	else if ("*Mac*OS*X*" iswm $1) {
		return "Mac OS X";
	}
	else if ("*Solaris*" iswm $1) {
		return "Solaris";
	}
	else if ("*Cisco*" iswm $1) {
		return "IOS";
	}
	else if ("*Printer*" iswm $1) {
		return "Printer";
	}
	else {
		return $1;
	}
}
