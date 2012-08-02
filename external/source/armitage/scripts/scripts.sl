#
# Cortana Script Manager...
#

import msf.*;
import java.awt.*;
import java.io.*;
import java.net.*;
import javax.swing.*;
import javax.imageio.*;
import ui.*;

import cortana.*;

sub getCortanaConsole {
	this('$console');
	if ($console is $null) {
		$console = [new console.Console: $preferences];
		logCheck($console, "all", "cortana");

		[$console updatePrompt: "\Ucortana\o> "];
		setupConsoleStyle($console);

		# make it so all I/O gets placed here...
		fork({
			[$cortana addTextListener: lambda({
				[$console append: "$1 $+ \n"];
			}, \$console)];
		}, \$console, \$cortana);

		# setup text processing
		[[$console getInput] addActionListener: lambda({
			local('$text');
			$text = [$1 getActionCommand];
			[$console append: "cortana> $text $+ \n"];
			[[$1 getSource] setText: ""];
			if ($text ne "") {
				fork({
					[$cortana processCommand: $text];
				}, \$cortana, \$text);
			}
		}, \$console)];

		# setup tab completion
		[new CortanaTabCompletion: $console, $cortana];
	}
	return $console;
}

sub updateScriptList {
	local('$table $model $script');
	($table, $model) = @_;
	[$model clear: 16];
	foreach $script (listScripts()) {
		[$model addEntry: %(name => $script, flags => "")];
	}
	[$model fireListeners];
}

sub showScriptConsole {
	[$frame addTab: "Cortana", getCortanaConsole(), $null];
}

sub showScriptManager {
	local('$dialog $table $model $load $unload $reload $console $scripts');
	$dialog = [new JPanel];
	[$dialog setLayout: [new BorderLayout]];

	($table, $model) = setupTable("name", @("name", "flags"), @());
	updateScriptList($table, $model);
	[$table setSelectionMode: [ListSelectionModel SINGLE_INTERVAL_SELECTION]];
	
	[$dialog add: [new JScrollPane: $table], [BorderLayout CENTER]];

	$load    = [new JButton: "Load"];
	$unload  = [new JButton: "Unload"];
	$console = [new JButton: "Console"];
	$scripts = [new JButton: "Scripts"];

	[$unload addActionListener: lambda({
		local('$script $s @scripts');
		$script = [$model getSelectedValue: $table];
		if ($script eq "") {
			return;
		}

		[$cortana unloadScript: $script];
		@scripts = listScripts();
		foreach $s (@scripts) {
			if ($s eq $script) {
				remove();
			}
		}
		saveScripts(@scripts);
		updateScriptList($table, $model);
	}, \$table, \$model)];

	[$load addActionListener: lambda({
		local('$file');
		$file = chooseFile($always => 1);
		if ($file is $null) {
			return;
		}

		try {
			[$cortana loadScript: $file];
			addScript($file);
			updateScriptList($table, $model);
		}
		catch $exception {
			if ($exception isa ^sleep.error.YourCodeSucksException) {
				showScriptError("Could not load $file $+ :\n\n" . [$exception formatErrors]);
			}
			else {
				showError($exception);
			}
		}
	}, \$table, \$model)];

	[$scripts addActionListener: gotoURL("https://github.com/rsmudge/cortana-scripts")];

	[$console addActionListener: &showScriptConsole];

	[$dialog add: center($load, $unload, $console, $scripts), [BorderLayout SOUTH]];
	[$frame addTab: "Scripts", $dialog, $null];
}

sub showScriptError {
	local('$dialog $text $close');
	$dialog = dialog("Script Error", 640, 320);

	$text = [new console.Display: $preferences];
	[$text setText: $1];
	[$text setFont: [Font decode: [$preferences getProperty: "console.font.font", "Monospaced BOLD 14"]]];
	[$text setForeground: [Color decode: [$preferences getProperty: "console.foreground.color", "#ffffff"]]];
	[$text setBackground: [Color decode: [$preferences getProperty: "console.background.color", "#000000"]]];

	$close = [new JButton: "Close"];
	[$close addActionListener: lambda({
		[$dialog setVisible: 0];
	}, \$dialog)];

	[$dialog add: $text, [BorderLayout CENTER]];
	[$dialog add: center($close), [BorderLayout SOUTH]];
	[$dialog show];
}

sub addScript {
	local('@scripts');
	@scripts = listScripts();
	push(@scripts, $1);
	saveScripts(@scripts);
}

sub listScripts {
	local('$scripts');
	$scripts = [$preferences getProperty: "cortana.scripts", ""];
	if ($scripts ne "") {
		return split("!!", $scripts);
	}
	return @();
}

sub saveScripts {
        [$preferences setProperty: "cortana.scripts", join("!!", $1)];
        savePreferences();
}

