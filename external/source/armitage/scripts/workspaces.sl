#
# CRUD for Dynamic Workspaces
#

import msf.*;
import java.awt.*;
import java.io.*;
import java.net.*;
import javax.swing.*;
import javax.imageio.*;
import ui.*;

sub newWorkspace {
	workspaceDialog(%(), @($1, $2), $title => "New Workspace", $button => "Add", $enable => 1);
}

sub editWorkspace {
	workspaceDialog($1, @($2, $3), $title => "Edit Workspace", $button => "Save", $enable => $null);
}

sub updateWorkspaceList {
	local('$table $model $workspace');
	($table, $model) = @_;
	[$model clear: 16];
	foreach $workspace (workspaces()) {
		[$model addEntry: $workspace];
	}
	[$model fireListeners];
}

sub listWorkspaces {
	local('$dialog $table $model $add $edit $delete $activate');
	$dialog = [new JPanel];
	[$dialog setLayout: [new BorderLayout]];

	($table, $model) = setupTable("name", @("name", "hosts", "ports", "os", "labels", "session"), @());
	updateWorkspaceList($table, $model);
	[$table setSelectionMode: [ListSelectionModel MULTIPLE_INTERVAL_SELECTION]];
	
	[$dialog add: [new JScrollPane: $table], [BorderLayout CENTER]];

	$activate = [new JButton: "Activate"];
	$add = [new JButton: "Add"];
	$edit = [new JButton: "Edit"];
	$delete = [new JButton: "Remove"];

	[$add addActionListener: lambda({
		newWorkspace($table, $model);
	}, \$table, \$model)];

	[$activate addActionListener: lambda({
		local('$sel $temp');
		$sel = selected($table, $model, "name");
		set_workspace($sel);
	}, \$table, \$model)];

	[$delete addActionListener: lambda({
		local('%names $workspace @workspaces');
		putAll(%names, [$model getSelectedValues: $table], { return 1; });
		@workspaces = workspaces();
		foreach $workspace (@workspaces) {
			if ($workspace['name'] in %names) {
				remove();
			}
		}
		saveWorkspaces(@workspaces);
		updateWorkspaceList($table, $model);
	}, \$table, \$model)];

	[$edit addActionListener: lambda({
		local('$sel $temp');
		$sel = selected($table, $model, "name");

		$temp = search(workspaces(), lambda({ 
			return iff($1["name"] eq $name, $1); 
		}, $name => $sel));

		if ($temp !is $null) {
			editWorkspace($temp, $table, $model);
		}
	}, \$table, \$model)];

	[$dialog add: center($activate, $add, $edit, $delete), [BorderLayout SOUTH]];
	[$frame addTab: "Workspaces", $dialog, $null];
}

sub workspaceDialog {
	local('$table $model');
	($table, $model) = $2;

	local('$dialog $name $host $ports $os $button $session $label');
	$dialog = dialog($title, 640, 480);
	[$dialog setLayout: [new GridLayout: 7, 1]];

	$name  = [new ATextField: $1['name'], 16];
	[$name setEnabled: $enable];
	$host  = [new ATextField: $1['hosts'], 16];
	$ports = [new ATextField: $1['ports'], 16];
	$os    = [new ATextField: $1['os'], 16];
	$label = [new ATextField: $1['labels'], 16];
	$session = [new JCheckBox: "Hosts with sessions only"];
	if ($1['session'] eq 1) {
		[$session setSelected: 1];
	}

	$button = [new JButton: $button];

	[$dialog add: label_for("Name:", 60, $name)]; 
	[$dialog add: label_for("Hosts:", 60, $host)]; 
	[$dialog add: label_for("Ports:", 60, $ports)]; 
	[$dialog add: label_for("OS:", 60, $os)]; 
	[$dialog add: label_for("Labels:", 60, $label)];
	[$dialog add: $session];

	[$dialog add: center($button)];
	[$dialog pack];
	[$dialog show];

	[$button addActionListener: lambda({
		# yay, we have a dialog...
		local('$n $h $p $o $s $l @workspaces $ws $temp');
		$n = [[$name getText] trim];
		$h = [strrep([$host getText], '*', '%', '?', '_') trim];
		$p = [[$ports getText] trim];
		$o = [strrep([$os getText], '*', '%', '?', '_') trim];
		$l = [[$label getText] trim];
		$s = [$session isSelected];

		# save the new menu
		$ws = workspace($n, $h, $p, $o, $s, $l);
		@workspaces = workspaces();
		foreach $temp (@workspaces) {
			if ($temp["name"] eq $n) {
				$temp = $ws;
				$ws = $null;
			}
		}

		if ($ws !is $null) {
			push(@workspaces, $ws);
		}
		saveWorkspaces(@workspaces);
		updateWorkspaceList($table, $model);

		[$dialog setVisible: 0];
	}, \$dialog, \$host, \$ports, \$os, \$name, \$session, \$table, \$model, \$label)];
}

sub reset_workspace {
	[$frame setTitle: $TITLE];
	thread({
		call($mclient, "db.filter", %());
	});
}

sub client_workspace_items {
	local('$index $workspace');

	item($1, 'Manage', 'M', {
		listWorkspaces();
	});

	separator($1);

	item($1, "Show All", "S", &reset_workspace);

	local('$x $y $workspace $name $title');
	$title = [$frame getTitle];
	foreach $y => $workspace (workspaces()) {
		$x = $y + 1;
		$name = $workspace['name'];

		if ($title eq "$TITLE - $name") {
			item($1, "$x $+ . $+ $name *", $x, lambda({
				set_workspace($name);
			}, \$name));
		}
		else {
			item($1, "$x $+ . $+ $name", $x, lambda({
				set_workspace($name);
			}, \$name));
		}

		# setup a keyboard shortcut for this workspace...
		[$frame bindKey: "Ctrl+ $+ $x", lambda({
			set_workspace($name);
		}, \$name)];
	}
}

sub set_workspace {
	local('$x $workspace');
	foreach $x => $workspace (workspaces()) {
		if ($workspace['name'] eq $1) {
			thread(lambda({
				call($mclient, "db.filter", $workspace);
			}, \$workspace));
			[$frame setTitle: "$TITLE - $1"];
			return;
		}
	}
}

sub workspace {
	return ohash(name => $1, hosts => $2, ports => $3, os => $4, session => $5, labels => $6);
}

sub workspaces {
	local('$ws @r $name $host $port $os $session $workspace $label');
	$ws = split("!!", [$preferences getProperty: "armitage.workspaces.menus", ""]);
	foreach $workspace ($ws) {
		if ($workspace ne "") {
			($name, $host, $port, $os, $session, $label) = split('@@', $workspace);
			push(@r, workspace($name, $host, $port, $os, $session, $label));
		}
	}
	return @r;
}

sub saveWorkspaces {
	[$preferences setProperty: "armitage.workspaces.menus", join("!!", map({ return join("@@", values($1)); }, $1))];
	savePreferences();
	setupWorkspaceShortcuts($1);
}

sub setupWorkspaceShortcuts {
	local('$x $y $workspace $name');
	foreach $y => $workspace ($1) {
		$name = $workspace['name'];
		$x = $y + 1;

		# setup a keyboard shortcut for this workspace...
		[$frame bindKey: "Ctrl+ $+ $x", lambda({
			set_workspace($name);
		}, \$name)];
	}

	[$frame bindKey: "Ctrl+Backspace", &reset_workspace];
}
