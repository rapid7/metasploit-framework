#
# Preferences
#

import table.*;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;

import java.io.*;
import msf.DatabaseImpl;
import ui.*;

global('$preferences $debug $motd $DATA_DIRECTORY $BASE_DIRECTORY $TITLE $CLIENT_CONFIG');

sub iHateYaml {
	local('$handle %result $current $text $key $value');
	$handle = openf($1);
	$current = "default";
	while $text (readln($handle)) {
		if ($text ismatch '(\w+):') {
			$current = matched()[0];
		} 
		else if ($text ismatch '\s+([\w\\.]+): [\'"]{0,1}([\w\\.]+)[\'"]{0,1}') {
			($key, $value) = matched();
			%result[$current][$key] = $value;
		}
	}
	return %result;
}

sub parseYaml {
	# all heil the Yaml file... holder of the database info.

	local('$database $user $pass $host $port $driver $object $file $setting');
	($file, $setting) = $2;
	try {
		$object = iHateYaml($file);
		$object = $object[$setting];

		if ($object !is $null) {
			($user, $pass, $database, $driver, $host, $port) = values($object, @("username", "password", "database", "adapter", "host", "port"));

			[$1 setProperty: "connect.db_connect.string", "$user $+ :\" $+ $pass $+ \"@ $+ $host $+ : $+ $port $+ / $+ $database"];
			[$1 setProperty: "connect.db_driver.string", $driver];
		}
	}
	catch $exception {
		showError("Couldn't load yaml file: $file $+ \n $+ $exception");
	}
}

sub loadPreferences {
	local('$file $prefs');
	$file = getFileProper(systemProperties()["user.home"], ".armitage.prop");
	if ($__frame__ !is $null && [$__frame__ getPreferences] !is $null) {
		$prefs = [$__frame__ getPreferences];
	}
	else {
		$prefs = [new Properties];
		if (-exists $file) {
			[$prefs load: [new java.io.FileInputStream: $file]];
		}
		else {
			[$prefs load: resource("resources/armitage.prop")];
		}

		if ($__frame__ !is $null) {
			[$__frame__ setPreferences: $prefs];
		}
	}

	# parse command line options here.

	global('$yaml_file $yaml_entry');
	local('%env');
	$yaml_entry = "production";

	%env = convertAll([System getenv]);
	if ("MSF_DATABASE_CONFIG" in %env) {
		$yaml_file = %env["MSF_DATABASE_CONFIG"];
	}
	
	while (size(@ARGV) > 0) {
		if (@ARGV[0] eq "-y" && -exists @ARGV[1]) {
			$yaml_file = @ARGV[1];
			@ARGV = sublist(@ARGV, 2);
		}
		else if (@ARGV[0] eq "-e") {
			$yaml_entry = @ARGV[1];
			@ARGV = sublist(@ARGV, 2);
		}
		else if (@ARGV[0] eq "--motd" || @ARGV[0] eq "-m") {
			$motd = @ARGV[1];
			@ARGV = sublist(@ARGV, 2);
			if (!-exists $motd) {
				warn("$motd file does not exist. Clients will not see MOTD.");
			}
		}
		else if (@ARGV[0] eq "--server") {
			break;
		}
		else if (@ARGV[0] eq "--client") {
			$CLIENT_CONFIG = @ARGV[1];
			@ARGV = sublist(@ARGV, 2);
			if (!-exists $CLIENT_CONFIG) {
				warn("$CLIENT_CONFIG file does not exist. Will show something else.");
			}
		}
		else {
			showError("I don't understand these arguments:\n" . join("\n", @ARGV));
			break;
		}
	}

	$TITLE = [$prefs getProperty: "armitage.application_title.string", "Armitage"];
	return $prefs;
}

sub loadDatabasePreferences {
	if ($yaml_file eq "" || !-exists $yaml_file) {
		if (thisIsTheirCommercialStuff()) {
			$yaml_file = getFileProper($BASE_DIRECTORY, "ui", "config", "database.yml");
		}
		else {
			$yaml_file = getFileProper($BASE_DIRECTORY, "config", "database.yml");
		}
	}

	if (!-exists $yaml_file) {
		throw [new RuntimeException: "I can not find a database.yml file. I *really* need it.\nTry setting MSF_DATABASE_CONFIG to a file that exists."];
	}
	else if (!-canread $yaml_file) {
		throw [new RuntimeException: "I do not have permission to read: $yaml_file $+ .\nRun me as root please."];
	}
	else {
		parseYaml($1, @($yaml_file, $yaml_entry));
	}
	return [$1 getProperty: "connect.db_connect.string"];
}

sub savePreferences {
	try {
		local('$file $exception');
		$file = getFileProper(systemProperties()["user.home"], ".armitage.prop");
		if (-exists getFileParent($file)) {
			[$preferences save: [new java.io.FileOutputStream: $file], "Armitage Configuration"];
		}
	}
	catch $exception {
		showError("I could not save your preferences:\n $+ $exception");
	}
}

$preferences = loadPreferences();

sub makePrefModel {
	local('$model');
	$model = [new GenericTableModel: @("component", "name", "type", "value"), "name", 32];
	return updatePrefModel($model);
}

sub updatePrefModel {
	local('$key $value $component $name $type $model');
	$model = $1;
	[$model setCellEditable: 3];
	
	foreach $key => $value (convertAll($preferences)) {
		($component, $name, $type) = split('\\.', $key);
		if ($type eq "color" || $type eq "shortcut" || $type eq "font" || $type eq "folder" || $type eq "file") {
			$type = "$type \u271A";
		}

		[$model addEntry: %(component => $component, name => $name, type => $type, value => $value, key => "$key")];
	}
	return $model;
}

# $select = [new JComboBox: @("Font", "Monospaced", "Courier New", "Courier")];
# $style  = [new JComboBox: @("Style", "Bold", "Italic", "Bold/Italic")];
# $size   = [new JComboBox: @("Size")];

sub selectListener {
	local('$f_font $f_style $f_size $describe');
	$f_font  = [$select getSelectedItem];
	$f_style = strrep(uc([$style getSelectedItem]), ' + ', '');
	$f_size  = [$size getSelectedItem];

	$describe = "$f_font $+ - $+ $f_style $+ - $+ $f_size";
	[$preview setFont: [Font decode: $describe]];
	[$dialog pack];
	return $describe;
}

sub createPreferencesTab {
	local('$table $model $panel $sorter $model $l');

	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];

	$model = makePrefModel();

	$table = [new ATable: $model];
	$sorter = [new TableRowSorter: $model];
	[$table setRowSorter: $sorter];

	# allow only one row to be selected at a time.
	[[$table getSelectionModel] setSelectionMode: [ListSelectionModel SINGLE_SELECTION]];
	[$panel add: [new JScrollPane: $table], [BorderLayout CENTER]];

	addMouseListener($table, lambda({
		if ($0 eq 'mouseClicked' && [$1 getClickCount] >= 2) {
			local('$sel $type $color $row $value');
			$sel  = [$model getSelectedValue: $table];
			$type = [$model getSelectedValueFromColumn: $table, "type"];
			$row = [$model getSelectedRow: $table];
			$value = [$model getSelectedValueFromColumn: $table, "value"];
		
			# strip the last two characters off.
			$type = substr($type, 0, -2);

			if ($type eq "color") {
				$color = [JColorChooser showDialog: $table, "pick a color", [Color decode: iff($value eq "", "#000000", $value)]];
	
				if ($color !is $null) {
					[$model setValueAtRow: $row, "value", '#' . substr(formatNumber(uint([$color getRGB]), 10, 16), 2)];
					[$model fireListeners];
				}
			}
			else if ($type eq "folder") {
				local('$file');
				$file = chooseFile($dirsonly => 1);
				if ($file !is $null) {
					[$model setValueAtRow: $row, "value", $file];
					[$model fireListeners];
				}
			}
			else if ($type eq "file") {
				local('$file');
				$file = chooseFile();
				if ($file !is $null) {
					[$model setValueAtRow: $row, "value", $file];
					[$model fireListeners];
				}
			}
			else if ($type eq "font") {
				local('$dialog $select $style $size $ok $cancel $preview $graphics $l $font $_style');
				$dialog = dialog("Choose a font", 640, 240);
				[$dialog setLayout: [new BorderLayout]];

				$font = [Font decode: $value];

				$graphics = [GraphicsEnvironment getLocalGraphicsEnvironment];

				# style..
				if ([$font isItalic] && [$font isBold]) { $_style = "Bold + Italic"; }
				else if ([$font isItalic]) { $_style = "Italic"; }
				else if ([$font isBold]) { $_style = "Bold"; }
				else { $_style = "Plain"; }

				$select = select([$graphics getAvailableFontFamilyNames], [$font getFamily]);
				$style  = select(@("Plain", "Bold", "Italic", "Bold + Italic"), $_style);
				$size   = select(@(5, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 23, 26, 30, 33, 38), [$font getSize] . "");

				$preview = [new JLabel: "nEWBS gET p0WNED by km-r4d h4x0rz"];

				$l = lambda(&selectListener, \$select, \$style, \$size, \$preview, \$dialog);
				map(lambda({ [$1 addItemListener: $l]; }, \$l), @($select, $style, $size));
				[$l];
			
				$ok = [new JButton: "Ok"];
				[$ok addActionListener: lambda({
					local('$font');
					[$model setValueAtRow: $row, "value", [$l]];
					[$model fireListeners];
					[$dialog setVisible: 0];
				}, \$dialog, \$model, \$row, \$l)];

				$cancel = [new JButton: "Cancel"];
				[$cancel addActionListener: lambda({ [$dialog setVisible: 0]; }, \$dialog)];

				[$dialog add: center($select, $style, $size), [BorderLayout NORTH]];
				[$dialog add: center($preview)];
				[$dialog add: center($ok, $cancel), [BorderLayout SOUTH]];
				[$dialog pack];
				[$dialog setVisible: 1];
				[$dialog show];
			}
			else if ($type eq "shortcut") {
				local('$dialog $label');
				$dialog = dialog("Shortcut", 100, 100);
				$label = [new JLabel: "Type the desired key:"];
				[$dialog add: $label];
				[$dialog pack];

				[$label setFocusTraversalKeys: [KeyboardFocusManager FORWARD_TRAVERSAL_KEYS], [new HashSet]];
				[$label setFocusTraversalKeys: [KeyboardFocusManager BACKWARD_TRAVERSAL_KEYS], [new HashSet]];
				[$label setFocusTraversalKeys: [KeyboardFocusManager UP_CYCLE_TRAVERSAL_KEYS], [new HashSet]];

				[$label addKeyListener: lambda({
					if ($0 eq "keyReleased") {
						[$model setValueAtRow: $row, "value", strrep([KeyStroke getKeyStrokeForEvent: $1], 'released', 'pressed')];
						[$model fireListeners];
						[$dialog setVisible: 0];
					}
				}, \$dialog, \$model, \$row)];

				[$dialog setVisible: 1];
				[$dialog show];
				[$label requestFocus];
			}
		}
	}, \$model, \$table));

	local('$button $reset');
	$button = [new JButton: "Save"];
	[$button addActionListener: lambda({
		local('$row $key $value');
		$preferences = [new Properties];
		foreach $row (convertAll([$model getRows])) {
			($key, $value) = values($row, @('key', 'value'));
			[$preferences setProperty: $key, $value];
		}
		savePreferences();
		showError("Preferences saved.");
	}, \$model)];

	$reset = [new JButton: "Reset"];
	[$reset addActionListener: lambda({
		local('$file');
		$file = getFileProper(systemProperties()["user.home"], ".armitage.prop");
		deleteFile($file);
		$preferences = loadPreferences();
		[$model clear: 256];
		updatePrefModel($model);
		[$model fireListeners];
	}, \$model)];

	[$panel add: center($button, $reset), [BorderLayout SOUTH]];

	local('$dialog');
	$dialog = dialog("Preferences", 640, 480);
	[$dialog add: $panel, [BorderLayout CENTER]];
	[$button addActionListener: lambda({ [$dialog setVisible: 0]; }, \$dialog)];
	[$dialog setVisible: 1];
	[$dialog show];
}

# sets up the Metasploit base file and the data directory file...
sub setupBaseDirectory {
	local('%o');
	%o = call($client, "module.options", "post", "multi/gather/dns_bruteforce");

	if ("NAMELIST" in %o && "default" in %o["NAMELIST"]) {
		$BASE_DIRECTORY = getFileParent(getFileParent(getFileParent(getFileParent(%o["NAMELIST"]["default"]))));
		$DATA_DIRECTORY = getFileParent(getFileParent(%o["NAMELIST"]["default"]));
	}
}

sub connectToDatabase {
	local('$dbuser $dbpass $dburl $database $dbstring');
	$dbstring = loadDatabasePreferences($preferences);

	if ($dbstring eq "") {
		throw [new RuntimeException: "could not find database settings"];
	}

	($dbuser, $dbpass, $dburl) = matches($dbstring, '(.*?):.(.*?).@(.*)');
	$database = [new DatabaseImpl];
	[$database connect: "jdbc:postgresql:// $+ $dburl", $dbuser, $dbpass];

	# connect to the database from metasploit if need be.
	cmd_safe("db_status", lambda({
		if ("* connected to *" !iswm $3) {
			cmd_safe("db_connect $dbstring", {
				warn(@_);
			});
		}
	}, \$dbstring));

	return $database;
}

sub dataDirectory {
	local('$f');

	if ([$preferences getProperty: "armitage.log_data_here.folder", ""] eq "") {
		[$preferences setProperty: "armitage.log_data_here.folder", getFileProper(systemProperties()["user.home"], ".armitage")];
		savePreferences();
	}

	$f = [$preferences getProperty: "armitage.log_data_here.folder"];
	if (-exists $f && !-canwrite $f) {
		println("I do not have permission to write to:\n $+ $f");
	}

	return $f;
}

sub thisIsTheirCommercialStuff {
	# check if we're living in a Metasploit 4.5+ installer environment.
	return iff("*app*pro*" iswm $BASE_DIRECTORY);
}
