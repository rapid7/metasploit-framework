#
# Loot browser (not yet complete... on hold until more post/ modules have loot)
#

import table.*;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;

import ui.*;

sub updateLootModel {
	thread(lambda({
		[Thread yield];
		local('$loots $entry');
		[$model clear: 16];
		$loots = call($mclient, "db.loots")["loots"];
		foreach $entry ($loots) {
			$entry["date"] = rtime($entry["updated_at"] / 1000L);
			$entry["type"] = $entry["ltype"];
			[$model addEntry: $entry];
		}
		[$model fireListeners];
	}, \$model));
}

sub showLoot {
	local('$dialog $v $button $refresh $text $data');
	$v = [$model getSelectedValue: $table];

	#
	# well then, file is binary... let's do something else with it, like save it.
	#
	if ($v !is $null && "*binary*" iswm [$model getSelectedValueFromColumn: $table, "content_type"]) {
		if ($client is $mclient) {
			[gotoFile([new java.io.File: getFileParent($v)])];
		}
		else {
			local('$name $save');
			$name = [$model getSelectedValueFromColumn: $table, "name"];
			$save = getFileName($name);
			thread(lambda({
				local('$handle $data');
				$data = getFileContent($v);
				$handle = openf("> $+ $save");
				writeb($handle, $data);
				closef($handle);
				[gotoFile([new java.io.File: cwd()])];
			}, \$v, \$save));
		}
		return;
	}
	else if ($v !is $null) {
		$dialog = [new JPanel];
		[$dialog setLayout: [new BorderLayout]];

		#$dialog = dialog("View Loot", 640, 480);
	
		$text = [new console.Display: $preferences];
		[$text setText: getFileContent($v)];
		[$text setFont: [Font decode: [$preferences getProperty: "console.font.font", "Monospaced BOLD 14"]]];
		[$text setForeground: [Color decode: [$preferences getProperty: "console.foreground.color", "#ffffff"]]];
		[$text setBackground: [Color decode: [$preferences getProperty: "console.background.color", "#000000"]]];

		$button = [new JButton: "Close"];
		[$button addActionListener: lambda({ [$dialog setVisible: 0]; }, \$dialog)];

		$refresh = [new JButton: "Refresh"];
		[$refresh addActionListener: lambda({ [$text setText: getFileContent($v)]; }, \$text, \$v)];

		[$dialog add: $text, [BorderLayout CENTER]];
		[$dialog add: center($refresh), [BorderLayout SOUTH]];
		[$frame addTab: "View", $dialog, $null, $v];
		#[$dialog show];
	}	
}

sub createLootBrowser {
	local('$table $model $panel $refresh $view $sorter $host');

	$model = [new GenericTableModel: @("host", "type", "info", "date"), "path", 16];

	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];

	$table = [new ATable: $model];
	$sorter = [new TableRowSorter: $model];
        [$sorter toggleSortOrder: 0];
	[$sorter setComparator: 0, &compareHosts];
	[$sorter setComparator: 3, {
		return convertDate($1) <=> convertDate($2);
	}];
	[$table setRowSorter: $sorter];

	[$panel add: [new JScrollPane: $table], [BorderLayout CENTER]];

	$view = [new JButton: "View"];

	addMouseListener($table, lambda({
		if ($0 eq "mousePressed" && [$1 getClickCount] >= 2) {
			showLoot(\$model, \$table);
		}
	}, \$model, \$table));

	[$view addActionListener: lambda({
		showLoot(\$model, \$table);
	}, \$model, \$table)];

	$refresh = [new JButton: "Refresh"];
	[$refresh addActionListener: lambda({
		updateLootModel(\$model);	
	}, \$model)];

	updateLootModel(\$model); 		

	[$panel add: center($view, $refresh), [BorderLayout SOUTH]];

	[$frame addTab: "Loot", $panel, $null];
}
