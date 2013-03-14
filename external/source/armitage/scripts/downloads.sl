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

sub updateDownloadModel {
	thread(lambda({
		local('$root $files $entry $findf $hosts $host');

		if ($client !is $mclient) {
			$files = call($mclient, "armitage.downloads");
		}
		else {
			$files = listDownloads(downloadDirectory());
		}

		[$model clear: 256];

		foreach $entry ($files) {
			$entry["date"] = rtime($entry["updated_at"] / 1000.0);
			[$model addEntry: $entry];
		}
		[$model fireListeners];
	}, \$model));
}

sub createDownloadBrowser {
	local('$table $model $panel $refresh $sorter $host $view $sync');

	$model = [new GenericTableModel: @("host", "name", "path", "size", "date"), "location", 16];

	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];

	$table = [new ATable: $model];
	setupSizeRenderer($table, "size");
	$sorter = [new TableRowSorter: $model];
        [$sorter toggleSortOrder: 0];
	[$sorter setComparator: 0, &compareHosts];
	[$sorter setComparator: 3, {
		return $1 <=> $2;
	}];
	[$sorter setComparator: 4, {
		return convertDate($1) <=> convertDate($2);
	}];
	[$table setRowSorter: $sorter];

	[$panel add: [new JScrollPane: $table], [BorderLayout CENTER]];

	addMouseListener($table, lambda({
		if ($0 eq "mousePressed" && [$1 getClickCount] >= 2) {
			showLoot(\$model, \$table, $getme => "location");
		}
	}, \$model, \$table));

	$view = [new JButton: "View"];

	if ($client is $mclient) {
		$sync = [new JButton: "Open Folder"];
		[$sync addActionListener: gotoFile([new java.io.File: getFileProper(dataDirectory(), "downloads")])];
	}
	else {
		$sync = [new JButton: "Sync Files"];
		[$sync addActionListener: lambda({
			downloadLoot(\$model, \$table, $getme => "location", $type => "downloads");
		}, \$model, \$table)];
	}

	[$view addActionListener: lambda({
		showLoot(\$model, \$table, $getme => "location");
	}, \$model, \$table)];

	$refresh = [new JButton: "Refresh"];
	[$refresh addActionListener: lambda({
		updateDownloadModel(\$model);	
	}, \$model)];

	updateDownloadModel(\$model); 		

	[$panel add: center($view, $sync, $refresh), [BorderLayout SOUTH]];

	[$frame addTab: "Downloads", $panel, $null];
}
