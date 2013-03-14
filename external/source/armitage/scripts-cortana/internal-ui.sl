#
# Armitage Extensions for Cortana
#

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;

import console.*;
import armitage.*;
import ui.*;
import java.io.*;
import javax.imageio.*;

# opens a generic tab with the component provided by the user.
sub open_tab {
	[$armitage addTab: "$1", $2, lambda({
		fire_event_local("tab_close", $panel, $arg, $title);
	}, $title => $1, $panel => $2, $arg => $3)];
	return $2;
}

sub _log_check {
	if ([$preferences getProperty: "armitage.log_everything.boolean", "true"] eq "true") {
		local('$today $logger');
		$today = formatDate("yyMMdd");
		if ($2 ne "") {
			mkdir(getFileProper(_data_directory(), $today, $2));
			$logger = [$shared getLogger: getFileProper(_data_directory(), $today, $2, "$3 $+ .log") ];
			[$1 writeToLog: $logger];
		}
	}
}

# "title", "log-sub-folder", popup hook, activity-console?
sub open_console_tab {
	local('$2 $3 $4');
	return spawn({
		global('$tab $console');
		$console = console();
		$tab = open_text_tab($title, $console, $log_folder, $popup_hook, $null, $q_activity, $metasploit => 1);
		[$console setDisplay: $tab];
		[new QueueTabCompletion: $tab, $console];

		on tab_close {
			[$console stop];
			quit();
		}

		_call_later_("&setupConsoleStyle", $tab);
		return $console;
	}, $title => $1, $log_folder => $2, $popup_hook => $3, $q_activity => $4);
}

# open_display_tab("title", $arg, @(buttons))
sub open_display_tab {
	local('$panel $display $3 $button');
	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];
	$display = [new console.Display: $preferences];

	if ($3 && size($3) > 0) {
		foreach $button ($3) {
			$button = [new JButton: "$button"];
			[$button addActionListener: lambda({
				fire_event_local("tab_display_click", $display, $arg, [[$1 getSource] getText]);
			}, \$display, $arg => $2)];
		}
		[$panel add: _center($3), [BorderLayout SOUTH]];
	}

	[$panel add: $display, [BorderLayout CENTER]];
        [[$display console] scrollRectToVisible: [new Rectangle: 0, 0, 0, 0]];
	open_tab($1, $panel, $2);
	return $display;
}

# "title", $argument, "log-sub-folder", popup hook, &tabcompletion, activity-console?
sub open_text_tab {
	local('$console $panel $2 $3 $4 $5 $6 $metasploit');

	# setup the console (if the user wants an activity console, give them one of those)
	if ($6) {
		$console = [new ActivityConsole: $preferences];
	}
	else {
		$console = [new Console: $preferences];
	}

	if (!$metasploit) {
		[[$console getInput] addActionListener: lambda({
			[[$1 getSource] setText: ""];
			fire_event_local("tab_text_input", $console, $arg, [$1 getActionCommand]);
		}, \$console, $arg => $2)];

		# add a word click listener too... why not.
		[$console addWordClickListener: lambda({
			fire_event_local("tab_text_click", $console, $arg, [$1 getActionCommand]);
		}, \$console, $arg => $2)];
	}

	# setup logging (if the scripter wants it)
	if ($3) {
		_log_check($console, $3, strrep($1, " ", "_"));
	}

	# setup popup menus (if the scripter wants them)
	if ($4) {
		# define some popup menus too
		[$console setPopupMenu: lambda({
			# $1 = word, $2 = event
			show_popup($2, $hook, $console, $1, $arg);
		}, \$console, $arg => $2, $hook => $4)];
	}

	# setup tab completion too -- may need to be a callback... not sure yet.
	if ($5) {
		[new cortana.gui.CortanaTabCompletion: $console, lambda({
			return [$f: $console, $arg, $1];	
		}, \$console, $arg => $2, $f => $5)];
	}

	# add the console to our display
	return open_tab($1, $console, $2);
}

sub append {
	[$1 append: "$2"];
}

sub prompt {
	[$1 setPrompt: $2];
}

sub input {
	[[$1 getInput] setText: $2];
}

sub clear_text {
	[$1 clear];
}

# "title", $argument, @cols, @rows, @buttons, "*hook*", multi?
sub open_table_tab {
	local('$panel $5 $6 $7');
	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];

	# add our table...
	($table, $model) = _setup_table($3[0], $3, $4, $7);
	[$panel add: [new JScrollPane: $table]];

	# setup our buttons...
	if ($5 && size($5) > 0) {
		foreach $button ($5) {
			$button = [new JButton: "$button"];
			[$button addActionListener: lambda({
				fire_event_local("tab_table_click", $table, $arg, [[$1 getSource] getText]);
			}, \$table, $arg => $2)];
		}
		[$panel add: _center($5), [BorderLayout SOUTH]];
	}

	# setup our popup menu...
	if ($6) {
		[$table addMouseListener: [new SafeMouseListener: lambda({
			if ([$1 isPopupTrigger]) {
				local('$sel');
				$sel = [[$table getModel] getSelectedValues: $table];
				show_popup($1, $hook, $table, $sel, $arg);
			}
		}, $hook => $6, \$table, $arg => $2)]];
	}

	open_tab($1, $panel, $2);
	return $table;
}

# @@ table_selected($table, "col1", "col2");
sub table_selected {
	return [[$1 getModel] getSelectedValuesFromColumns: $1, sublist(@_, 1)];
}

sub table_selected_single {
	return flatten(table_selected($1, $2));
}

# table_set($table, @rows)
sub table_set {
	later(lambda({
		local('$model $row');
		$model = [$a getModel];
		[$model clear: size($b) * 2];
		foreach $row ($b) {
			[$model addEntry: $row];
		}
		[$model fireListeners];
	}, $a => $1, $b => $2));
}

# table_set($table, @rows)
sub table_update {
	later(lambda({
		[$a markSelections];
		table_set($a, $b);
		[$a restoreSelections];
	}, $a => $1, $b => $2));
}

# table_sorter($table, index, &function);
sub table_sorter {
	[[$1 getRowSorter] setComparator: $2, $3];
}

# table_sorter_host($table, index)
sub table_sorter_host {
	table_sorter($1, $2, &_compare_hosts);
}

# table_sort_date($table, index)
sub table_sorter_date {
	table_sorter($1, $2, { return parse_msf_date($1) <=> parse_msf_date($2); });
}

# $image = open_image_tab("title", $arg, @(buttons...))
sub open_image_tab {
	local('$panel @buttons $b');
	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];
	
	$image = [new ZoomableImage];
	[$panel add: [new JScrollPane: $image], [BorderLayout CENTER]];

	if ($3 !is $null && size($3) > 0) {
		foreach $button ($3) {
			$b = [new JButton: $button];
			[$b addActionListener: lambda({
				fire_event_local("tab_image_click", $image, $arg, $button);
			}, \$image, $button => "$button", $arg => $2)];
			push(@buttons, $b);
		}
		[$panel add: _center(@buttons), [BorderLayout SOUTH]];
	}

	open_tab($1, $panel, $2);
	return $image;
}

# set_image($image, "/path/to/image.jpg", "host|all", "type");
sub set_image {
	local('$image');
	if (size(@_) == 4) {
		log_file($2, $3, $4);
	}
	
	warn("Opening: $2");
	$image = [ImageIO read: [new File: $2]];
	if ($image !is $null) {
		dispatch_event({ 
			[$container setIcon: [new ImageIcon: $image]]; 
		}, $container => $1, \$image);
	}
}
