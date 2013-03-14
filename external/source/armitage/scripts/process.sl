#
# Process Browser (for Meterpreter)
#

import table.*;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;

import ui.*;

global('%processes');
%processes = ohash();

setMissPolicy(%processes, { return [new GenericTableModel: @("PID", "Name", "Arch", "Session", "User", "Path"), "PID", 128]; });

sub parseProcessList {
	if ($0 eq "end") {
		local('@rows $row');
		[%processes[$1] clear: 128];
		@rows = parseTextTable($2, @("PID", "PPID", "Name", "Arch", "Session", "User", "Path"));
		if (size(@rows) == 0) {
			# REMOVEME--this is a backwards compatability hack.
			@rows = parseTextTable($2, @("PID", "Name", "Arch", "Session", "User", "Path"));
		}

		# this is the format for Java meterpreter
		if (size(@rows) == 0) {
			@rows = parseTextTable($2, @("PID", "Name", "Arch", "User", "Path"));
		}

		foreach $row (@rows) {
			[%processes[$1] addEntry: $row];
		}
		[%processes[$1] fireListeners];
	}
}

%handlers["ps"] = &parseProcessList;
%handlers["migrate"] = { if ($0 eq "begin") { showError("$2"); } };

sub createProcessBrowser {
	local('$table $model $panel $sorter');

	$model = %processes[$1];

	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];

	$table = [new ATable: $model];
	$sorter = [new TableRowSorter: $model];
	[$sorter toggleSortOrder: 0];
	[$table setRowSorter: $sorter];

	# setup popup hook for processes
	addMouseListener($table, lambda({
		if ([$1 isPopupTrigger]) {
			local('$r');
			$r = [$model getSelectedValuesFromColumns: $table, @("PID", "Name", "User", "Path")];
			if (size($r) > 0) {
				installMenu($1, "process", $r);
			}
		}
        }, \$table, \$model));

	# allow only one row to be selected at a time.

	[$sorter setComparator: 0, {
		return $1 <=> $2;
	}];

	[$panel add: [new JScrollPane: $table], [BorderLayout CENTER]];

	local('$a $b $bb $bbb $c');
	$a = [new JButton: "Kill"];
	[$a addActionListener: lambda({ 
		local('$procs $v');
		$procs = [$model getSelectedValues: $table];
		foreach $v ($procs) {
			m_cmd($m, "kill $v"); 
		}	
		sleep(250);
		m_cmd($m, "ps"); 
	}, $m => $1, \$table, \$model)];

	$b = [new JButton: "Migrate"];
	[$b addActionListener: lambda({ 
		local('$v');
		$v = [$model getSelectedValue: $table];
		if ($v !is $null) {
			m_cmd($m, "migrate $v"); 
		}	
	}, $m => $1, \$table, \$model)];

	$bb = [new JButton: "Log Keystrokes"];
	[$bb addActionListener: lambda({
		local('$v');
		$v = [$model getSelectedValue: $table];
		if ($v !is $null) {
			launch_dialog("Log Keystrokes", "post", "windows/capture/keylog_recorder", 1, $null, %(SESSION => $m, MIGRATE => 1, ShowKeystrokes => 1, PID => $v, CAPTURE_TYPE => "pid"));
		}	
	}, $m => $1, \$table, \$model)];

	$bbb = [new JButton: "Steal Token"];
	[$bbb addActionListener: lambda({
		local('$v');
		$v = [$model getSelectedValue: $table];
		if ($v !is $null) {
			m_cmd_callback($m, "steal_token $v", { if ($0 eq "end") { showError(["$2" trim]); } }); 
		}
	}, $m => $1, \$table, \$model)];

	$c = [new JButton: "Refresh"];
	[$c addActionListener: 
		lambda({ 
			m_cmd($m, "ps"); 
		}, $m => $1)
	];

	[$panel add: center($a, $b, $bb, $bbb, $c), [BorderLayout SOUTH]];

	[$frame addTab: "Processes $1", $panel, $null, "Processes " . sessionToHost($1)];
	m_cmd($1, "ps");
}
