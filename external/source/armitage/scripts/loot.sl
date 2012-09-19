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

sub downloadLoot {
	thread(lambda({
		local('$dest');
		#$dest = chooseFile($title => "Where shall I save these files?", $dirsonly => 1, $always => 1);
		$dest = getFileProper(dataDirectory(), $type);
		mkdir($dest);
		_downloadLoot(\$model, \$table, \$getme, \$dest, $dtype => $type);
	}, \$model, \$table, \$getme, \$type));
}

sub _downloadLoot {
	local('$progress $entries $index $host $location $name $type $when $loot $path');
	$entries = [$model getSelectedValuesFromColumns: $table, @('host', $getme, 'name', 'content_type', 'updated_at', 'path')];
	$progress = [new ProgressMonitor: $frame, "Download Data", "", 0, size($entries)];
	foreach $index => $loot ($entries) {
		($host, $location, $name, $type, $when, $path) = $loot;
		[$progress setNote: $name];

		# make the folder to store our downloads into
		local('$handle $data $file');
		if ($dtype eq "downloads") {
			$file = getFileProper($dest, $host, strrep($path, ':', ''), $name);
		}
		else {
			$file = getFileProper($dest, $host, $name);
		}
		mkdir(getFileParent($file));

		# dump the file contents there...
		$data = getFileContent($location);
		$handle = openf("> $+ $file");
		writeb($handle, $data);
		closef($handle);

		[$progress setProgress: $index + 1];

		if ([$progress isCanceled]) {
			break;
		}
	}

	dispatchEvent(lambda({
		[$progress close];
		showError("File(s) saved to:\n $+ $dest");
		[gotoFile([new java.io.File: $dest])];
	}, \$dest, \$progress));
}

sub showLoot {
	thread(lambda(&_showLoot, \$model, \$table, \$getme));
}

sub _postLoot {
	local('$host $location $name $type $when');
	($host, $location, $name, $type, $when) = $1;

	[$2 append: "
\c9#
\c9# $host $+ : $name 
\c9#\n"];

	if ("*binary*" iswm $type) {
		[$2 append: "\c4This is a binary file\n"];
	}
	else {
		[$2 append: getFileContent($location)];
	}
}

sub _showLoot {
	local('$loot $entries $dialog $display $refresh');

	$dialog = [new JPanel];
	[$dialog setLayout: [new BorderLayout]];
	$display = [new console.Display: $preferences];

	$entries = [$model getSelectedValuesFromColumns: $table, @('host', $getme, 'name', 'content_type', 'updated_at')];

	foreach $loot ($entries) {
		_postLoot($loot, $display);
		yield 10;
	}

	$refresh = [new JButton: "Refresh"];
	[$refresh addActionListener: lambda({
		local('$r');
		$r = [[$display console] getVisibleRect];
		[$display setText: ""];
		thread(lambda({
			local('$loot');

			foreach $loot ($entries) {
				_postLoot($loot, $display);
				yield 10;
			}

			dispatchEvent(lambda({
				[[$display console] scrollRectToVisible: $r];
			}, \$display, \$r));
		}, \$entries, \$display, \$r));
	}, \$entries, \$display)];

	[$dialog add: $display, [BorderLayout CENTER]];
	[[$display console] scrollRectToVisible: [new Rectangle: 0, 0, 0, 0]];
	[$dialog add: center($refresh), [BorderLayout SOUTH]];
	[$frame addTab: "View", $dialog, $null, $null];
}

sub createLootBrowser {
	local('$table $model $panel $refresh $view $sorter $host $sync');

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
			showLoot(\$model, \$table, $getme => "path");
		}
	}, \$model, \$table));

	$sync = [new JButton: "Sync Files"];
	[$sync addActionListener: lambda({
		downloadLoot(\$model, \$table, $getme => "path", $type => "loots");
	}, \$model, \$table)];

	[$view addActionListener: lambda({
		showLoot(\$model, \$table, $getme => "path");
	}, \$model, \$table)];

	$refresh = [new JButton: "Refresh"];
	[$refresh addActionListener: lambda({
		updateLootModel(\$model);	
	}, \$model)];

	updateLootModel(\$model); 		

	if ($client is $mclient) {
		[$panel add: center($view, $refresh), [BorderLayout SOUTH]];
	}
	else {
		[$panel add: center($view, $sync, $refresh), [BorderLayout SOUTH]];
	}

	[$frame addTab: "Loot", $panel, $null];
}
