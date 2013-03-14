import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;

import msf.*;
import table.*;

import graph.*;
import ui.*;

sub maskToCIDR {
	local ('$x');
	$x = strlen(strrep(formatNumber([Route ipToLong: $1], 10, 2), "0", ""));
	return $x;
}

sub arp_scan_function  {
	local('$host $mask');
	$host = [$model getSelectedValueFromColumn: $table, "host"];
	$mask = [$model getSelectedValueFromColumn: $table, "mask"];
	
	if ($host ne "" && $mask ne "") {
		elog("ARP scan: $host $+ /" . maskToCIDR($mask) . " via $sid", sessionToHost($sid));
		module_execute("post", "windows/gather/arp_scanner", %(THREADS => 24, SESSION => $sid, RHOSTS => "$host $+ /" . maskToCIDR($mask)));
	}
	[$dialog setVisible: 0];
}

sub ping_sweep_function  {
	local('$host $mask');
	$host = [$model getSelectedValueFromColumn: $table, "host"];
	$mask = [$model getSelectedValueFromColumn: $table, "mask"];
	
	if ($host ne "" && $mask ne "") {
		elog("ping sweep: $host $+ /" . maskToCIDR($mask) . " via $sid", sessionToHost($sid));
		module_execute("post", "multi/gather/ping_sweep", %(SESSION => $sid, RHOSTS => "$host $+ /" . maskToCIDR($mask)));
	}
	[$dialog setVisible: 0];
}

sub add_pivot_function  {
	local('$host $mask');
	$host = [$model getSelectedValueFromColumn: $table, "host"];
	$mask = [$model getSelectedValueFromColumn: $table, "mask"];
	
	if ($host ne "" && $mask ne "") {
		elog("added pivot: $host $mask $sid", sessionToHost($sid));
		cmd_safe("route add $host $mask $sid", {
			if ($3 ne "") { showError($3); } 
		});
	}
	[$dialog setVisible: 0];
}

#
# pop up a dialog to start our attack with... fun fun fun
#

# pivot_dialog($sid, $network output?))
sub pivot_dialog {
	if ($0 eq "end") {
		local('$data $platform');
		$data = sessionData($1);
		if ($data && 'platform' in $data) {
			$platform = $data['platform'];
		}

		# parse through the routing table...
		local('@tempr $entry $host $mask $gateway @routes');
		@tempr = parseTextTable($2, @('Subnet', 'Netmask', 'Gateway', 'Metric', 'Interface'));
		foreach $entry (@tempr) {
			($host, $mask, $gateway) = values($entry, @('Subnet', 'Netmask', 'Gateway'));

			if ($host ne "127.0.0.1" && $host ne "127.0.0.0" && $host ne "224.0.0.0" && $host ne "0.0.0.0" && $mask ne "255.255.255.255") {
				# work around a Metasploit bug that returns the host IP/mask rather than the actual route info
				# for Java meterpreter... 
				if ($platform eq "java/java") {
					local('$a $b $c $d');
					($a, $b, $c, $d) = split('\\.', $host);

					if ($mask eq "255.255.255.0") {
						$host = "$a $+ . $+ $b $+ . $+ $c $+ .0";
					}
					else if ($mask eq "255.255.0.0") {
						$host = "$a $+ . $+ $b $+ .0.0";
					}
					else if ($mask eq "255.0.0.0") {
						$host = "$a $+ .0.0.0";
					}
				}

				push(@routes, %(host => $host, mask => $mask, gateway => $gateway));
			}
		}

		# ok, let's close down this handler...
		$platform = $null;
		$handler = $null;
		%handlers["route"] = $null;

		if (size(@routes) == 0) {
			# eventually, we're going to need to parse IPv6 stuff...
			return;
		}

		local('$dialog $model $table $sorter $center $a $route $button');
		$dialog = [new JDialog: $__frame__, $title, 0];
		[$dialog setSize: 320, 240];
		[$dialog setLayout: [new BorderLayout]];
		[$dialog setLocationRelativeTo: $__frame__];

		[$dialog setLayout: [new BorderLayout]];
	
		$model = [new GenericTableModel: @("host", "mask"), "Option", 8];
		foreach $route (@routes) {
			[$model _addEntry: $route];
		}

		$table = [new ATable: $model];
	        [[$table getSelectionModel] setSelectionMode: [ListSelectionModel SINGLE_SELECTION]];
		$sorter = [new TableRowSorter: $model];
		[$table setRowSorter: $sorter];
			
		if (size(@routes) > 0) {
		        [[$table getSelectionModel] addSelectionInterval: 0, 0];
		}

		$center = [new JScrollPane: $table];
	
		$a = [new JPanel];
		[$a setLayout: [new FlowLayout: [FlowLayout CENTER]]];

		$button = [new JButton: $label];
		[$button addActionListener: lambda($function, \$table, \$model, \$dialog, \$sid)];

		[$a add: $button];

		[$dialog add: $center, [BorderLayout CENTER]];
		[$dialog add: $a, [BorderLayout SOUTH]];

		[$button requestFocus];
		[$dialog setVisible: 1];
	}
}

sub setupPivotDialog {
	return lambda({
		%handlers["route"] = lambda(&pivot_dialog, \$sid, $title => "Add Pivot", $label => "Add Pivot", $function => &add_pivot_function);
		m_cmd($sid, "route");
	}, $sid => "$1");
}

sub setupArpScanDialog {
	return lambda({
		%handlers["route"] = lambda(&pivot_dialog, \$sid, $title => "ARP Scan", $label => "ARP Scan", $function => &arp_scan_function);
		m_cmd($sid, "route");
	}, $sid => "$1");
}

sub setupPingSweepDialog {
	return lambda({
		%handlers["route"] = lambda(&pivot_dialog, \$sid, $title => "Ping Sweep", $label => "Ping Sweep", $function => &ping_sweep_function);
		m_cmd($sid, "route");
	}, $sid => "$1");
}

# killPivots(sid, session data
sub killPivots {
	local('$route');
	foreach $route (split(',', $2['routes'])) {
		cmd_safe("route remove " . strrep($route, '/', ' ') . " $1");
	}

	elog("removed pivot: " . $2['routes']);
}
