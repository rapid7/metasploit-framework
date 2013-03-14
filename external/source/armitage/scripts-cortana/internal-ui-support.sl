#
# UI Support Functions
#

import armitage.*; 
import ui.*;
import table.*;
import graph.*;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.table.*;

import java.awt.datatransfer.*;

# ($table, $model) = _setup_table("lead", @cols, @rows, multi?)
sub _setup_table {
	local('$table $model $sorter $row');
	$model = [new GenericTableModel: $2, $1, 8];
	foreach $row ($3) {
		[$model _addEntry: $row];
	}

	$table = [new ATable: $model];

	if ($4) {
		[[$table getSelectionModel] setSelectionMode: [ListSelectionModel MULTIPLE_INTERVAL_SELECTION]];
	}
	else {
		[[$table getSelectionModel] setSelectionMode: [ListSelectionModel SINGLE_SELECTION]];
	}

	$sorter = [new TableRowSorter: $model];
	[$table setRowSorter: $sorter];
	
	return @($table, $model);
}

sub _center {
	local('$panel $c');
	$panel = [new JPanel];
	[$panel setLayout: [new FlowLayout: [FlowLayout CENTER]]];

	foreach $c ($1) {
		[$panel add: $c];
	}

	return $panel;
}

sub _compare_hosts {
	if ($1 eq "unknown") {
		return _compare_hosts("0.0.0.0", $2);
	}
	else if ($2 eq "unknown") {
		return _compare_hosts($1, "0.0.0.0");
	}
	else {
		return [Route ipToLong: $1] <=> [Route ipToLong: $2];
	}
}

sub clipboard_set {
        local('$sel $cb');
        $sel = [new StringSelection: $1];
        $cb = [[Toolkit getDefaultToolkit] getSystemSelection];
        if ($cb !is $null) {
                [$cb setContents: $sel, $null];
        }

        $cb = [[Toolkit getDefaultToolkit] getSystemClipboard];
        if ($cb !is $null) {
                [$cb setContents: $sel, $null];
        }
}

sub prompt_file_save {
	local('$fc $1');
	$fc = [new JFileChooser];

	if ($1 !is $null) {
		[$fc setSelectedFile: [new java.io.File: $1]];
	}

	[$fc showSaveDialog: $armitage];
	return [$fc getSelectedFile];
}

sub prompt_file_open {
	local('$fc $1 $2 $3 $4');
	$fc = [new JFileChooser];

	if ($1 !is $null) { [$fc setDialogTitle: $1]; }
	if ($2 !is $null) { [$fc setCurrentDirectory: [new java.io.File: $2]]; }
	if ($3 !is $null) { [$fc setMultiSelectionEnabled: $3]; }
	if ($4 !is $null) { [$fc setFileSelectionMode: [JFileChooser DIRECTORIES_ONLY]]; }

	[$fc showOpenDialog: $armitage];

	if ($3) {
		return [$fc getSelectedFiles];
	}
	else {
		return [$fc getSelectedFile];
	}
}

sub url_open {
	[[Desktop getDesktop] browse: [[new java.net.URL: $1] toURI]];
}

sub show_message {
	later({
		[JOptionPane showMessageDialog: $armitage, $1];
	}, $1);
}

sub prompt_text {
	local('$2');
	return [JOptionPane showInputDialog: "$1", "$2"];
}

sub prompt_confirm {
	return [JOptionPane showConfirmDialog: $null, $1, $2, [JOptionPane YES_NO_OPTION]];
}

sub targets_selected {
	return [[$shared get: "targets"] getSelectedHosts];
}

# launch_attack("exploit", @hosts)
sub launch_attack {
	local('$a $b');
	$a = call("module.info", "exploit", $1);
	$b = call("module.options", "exploit", $1);
	_call_async_("&attack_dialog", $a, $b, $2, $1);
}

# laubch_module("title", "top-level", "path", visible?, @(), %options)
sub launch_module {
	_call_async_("&launch_dialog", $1, $2, $3, 1, $null, $4);
}

# launch_login("service", "port", @hosts)
sub launch_login {
	_call_async_("&show_login_dialog", $service => %(port => $2, name => $1), $hosts => $3);
}

sub launch_psexec {
	_call_async_("&show_psexec_dialog", $hosts => $1);
}

sub run_export_data {
	local('$1');
	if ($1 is $null) {
		_call_async_("&generateArtifacts", %());
	}
	else {
		_call_async_("&generateArtifacts", $1);
	}
}

sub open_script_console {
	_call_async_("&showScriptConsole");
}

sub pref_get {
	local('$2');
	return [$preferences getProperty: $1, $2];
}

sub pref_set {
	[$preferences setProperty: $1, $2];
	_call_("&savePreferences");
}

sub show_modules {
	local('$1 $2 $3 $4');
	_call_async_("&showModules", $1, $2, $3, $4);
}

sub open_file_browser {
	_call_async_("&createFileBrowser", $1, session_data($1)['platform']);
}

sub switch_display {
	pref_set("armitage.string.target_view", $1);
	_call_async_("&createDashboard");
}

sub run_module {
	_call_async_("&module_execute", $1, $2, $3);
}

sub run_scans {
	_call_async_("&launch_msf_scans", $1);
}

# creates a list dialog,
# $1 = title, $2 = @(buttons), $3 = columns, $4 = rows
sub prompt_list {
	local('$dialog $panel $table $row $model $button $sorter $width $height $buttons $t');

	# setup width and height
	if (size(@_) >= 5) {
		($width, $height) = sublist(@_, 5);
	}

	if ($width is $null) { $width = 320; }
	if ($height is $null) { $height = 200; }

	$dialog = _dialog($1, $width, $height);
	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];
	
	($table, $model) = _setupTable($3[0], $3, $4);
	[$panel add: [new JScrollPane: $table], [BorderLayout CENTER]];
	
	#
	# setup our buttons for success...
	#
	$buttons = copy($2);
	foreach $button ($buttons) {
		$t = "$button";
		$button = [new JButton: $t];
		[$button addActionListener: lambda({
			local('$sel $row');
			$sel = [$model getSelectedValueFromColumn: $table, $lead];
			if ($sel !is $null) {
				$row = [$model getSelectedValuesFromColumns: $table, $cols][0];
				fire_event_local("item_selected", $title, $sel, $row);
			}
			[$dialog setVisible: 0];
		}, \$dialog, $title => $t, \$model, \$table, $lead => $3[0], $cols => $3)];
	}

	local('$south');
	$south = [new JPanel];
        [$south setLayout: [new BoxLayout: $south, [BoxLayout Y_AXIS]]];
	[$south add: _center($buttons)];

	[$panel add: $south, [BorderLayout SOUTH]];
	[$dialog add: $panel, [BorderLayout CENTER]];
	[$dialog show];
	[$dialog setVisible: 1];
}

sub _dialog {
	local('$dialog $4');
	$dialog = [new JDialog: $frame, $1];
	[$dialog setSize: $2, $3];
	[$dialog setLayout: [new BorderLayout]];
	[$dialog setLocationRelativeTo: $frame];
	return $dialog;
}

sub _setupTable {
	local('$table $model $sorter $row');
	$model = [new GenericTableModel: $2, $1, 8];
	foreach $row ($3) {
		[$model _addEntry: $row];
	}

	$table = [new ATable: $model];
	[[$table getSelectionModel] setSelectionMode: [ListSelectionModel SINGLE_SELECTION]];
	$sorter = [new TableRowSorter: $model];
	[$table setRowSorter: $sorter];

	return @($table, $model);
}

sub log_file {
	if ([$preferences getProperty: "armitage.log_everything.boolean", "true"] eq "true") {
		local('$today $handle $data $out');
		$today = formatDate("yyMMdd");
		if (-exists $1 && -canread $1) {
			mkdir(getFileProper(_data_directory(), $today, $2, $3));

			# read in the file
			$handle = openf($1);
			$data = readb($handle, -1);
			closef($handle);

			# write it out.
			$out = getFileProper(_data_directory(), $today, $2, $3, getFileName($1));
			$handle = openf("> $+ $out");
			writeb($handle, $data);
			closef($handle);
		}
		else {
			warn("Could not find file: $1");
		}
	}
}

