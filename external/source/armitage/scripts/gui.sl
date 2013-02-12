#
# This file defines the main GUI and loads additional modules
#

debug(7 | 34);

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.border.*;
import javax.swing.table.*;
import javax.swing.tree.*;
import javax.imageio.*;

import java.awt.*;
import java.awt.image.*;
import java.awt.event.*;
import java.awt.datatransfer.*;

import graph.*;
import armitage.*;
import table.*;
import ui.*;

# Create a new menu, returns the menu, you have to attach it to something
# menu([$parent], "Name", 'Accelerator')
sub menu {
	return invoke(&_menu, filter_data_array("menu_parent", @_));
}

sub _menu {
	local('$menu');
	if (size(@_) == 2) {
		$menu = [new JMenu: $1];

		if ($2 !is $null) {
			[$menu setMnemonic: casti(charAt($2, 0), 'c')];
		}
	}
	else {
		$menu = invoke(&menu, sublist(@_, 1));
		[$1 add: $menu];
	}
	return $menu;
}

sub dynmenu {
	local('$menu');
	$menu = [new DynamicMenu: $2];
	[$menu setMnemonic: casti(charAt($3, 0), 'c')];
	[$menu setHandler: $4];
	[$1 add: $menu];
	return $menu;
}

# create a separator in the parent menu
sub separator {
	[$1 addSeparator];
}

# create a menu item, attaches it to the specified parent (based on the Name)
# item($parent, "Name", 'accelerator', &listener)
sub item {
	return invoke(&_item, filter_data_array("menu_item", @_));
}

sub _item {
	local('$item');
	if ($1 is $null || $2 is $null) {
		return;
	}

	$item = [new JMenuItem: $2];
	if ($3 !is $null) {
		[$item setMnemonic: casti(charAt($3, 0), 'c')];
	}
	
	if ($4 is $null) { warn("Incomplete: " . @_); }

	[$item addActionListener: lambda({ 
		invoke($function);
	}, $function => $4)];

	[$1 add: $item];
	return $item;
}

sub dispatchEvent {
	if ([SwingUtilities isEventDispatchThread]) {
		[$1];
	}
	else {
		[SwingUtilities invokeLater: $1];
	}
}

sub showError {
	dispatchEvent(lambda({
		[JOptionPane showMessageDialog: $__frame__, $message];
	}, $message => $1));
}

sub showErrorAndQuit {
	[JOptionPane showMessageDialog: $__frame__, $1];
	[$__frame__ closeConnect];
}

sub ask {
	local('$2');
	return [JOptionPane showInputDialog: "$1", "$2"];
}

# askYesNo("title", "text")
sub askYesNo {
	return [JOptionPane showConfirmDialog: $null, $1, $2, [JOptionPane YES_NO_OPTION]];
}

sub chooseFile {
	local('$fc $file $title $sel $dir $multi $always $dirsonly');

	if ($REMOTE && $always is $null) {
		if ($client !is $mclient) {
			local('$file');
			$file = chooseFile(\$title, \$file, \$sel, \$dir, \$dirsonly, \$multi, \$fc, $always => 1);
			if (-exists $file) {
				warn("Uploading $file");
				return uploadFile($file);
			}
			return "";
		}
		else {
			return ask("Please type a file name:");
		}
	}


	$fc = [new JFileChooser];

	if ($title !is $null) {
		[$fc setDialogTitle: $title];
	}

	if ($sel !is $null) {
		[$fc setSelectedFile: [new java.io.File: $sel]];
	}

	if ($dir !is $null) {
		[$fc setCurrentDirectory: [new java.io.File: $dir]];
	}

	if ($multi !is $null) {
		[$fc setMultiSelectionEnabled: 1];
	}

	if ($dirsonly !is $null) {
		[$fc setFileSelectionMode: [JFileChooser DIRECTORIES_ONLY]];
	}

	[$fc showOpenDialog: $__frame__];

	if ($multi) {
		return [$fc getSelectedFiles];
	}
	else {
		$file = [$fc getSelectedFile];
		if ($file !is $null) {
			if (-exists $file) {
				return $file;
			}
			showError("$file does not exist!");
		}
	}
}

sub saveFile2 {
	local('$fc $file $sel');
	$fc = [new JFileChooser];

	if ($sel !is $null) {
		[$fc setSelectedFile: [new java.io.File: $sel]];
	}

	if ([$fc showSaveDialog: $__frame__] == 0) {
		$file = [$fc getSelectedFile];
		if ($file !is $null) {
			return $file;
		}
	}
}

sub saveFile {
	local('$fc $file');
	$fc = [new JFileChooser];
	[$fc showSaveDialog: $__frame__];
	$file = [$fc getSelectedFile];
	if ($file !is $null) {
		local('$ihandle $data $ohandle');
		$ihandle = openf($1);
		$ohandle = openf("> $+ $file");
		while $data (readb($ihandle, 8192)) {
			writeb($ohandle, $data);
		}
		closef($ihandle);
		closef($ohandle);
	}
}

# label_for("text", width, component)
sub label_for {
	local('$panel $label $size');
	$panel = [new JPanel];
	[$panel setLayout: [new FlowLayout: [FlowLayout LEFT]]];

	$label = [new JLabel: $1];
	
	$size = [$label getPreferredSize];
	[$label setPreferredSize: [new Dimension: $2, [$size getHeight]]];

	[$panel add: $label];
	[$panel add: $3];

	if (size(@_) >= 4) {
		[$panel add: $4];
	}

	return $panel;
}

sub center {
	local('$panel $c');
	$panel = [new JPanel];
	[$panel setLayout: [new FlowLayout: [FlowLayout CENTER]]];

	foreach $c (@_) {
		[$panel add: $c];
	}

	return $panel;
}

sub left {
	local('$panel $c');
	$panel = [new JPanel];
	[$panel setLayout: [new FlowLayout: [FlowLayout LEFT]]];

	foreach $c (@_) {
		[$panel add: $c];
	}

	return $panel;
}

sub dialog {
	local('$dialog $4');
        $dialog = [new JDialog: $__frame__, $1];
        [$dialog setSize: $2, $3];
        [$dialog setLayout: [new BorderLayout]];
        [$dialog setLocationRelativeTo: $__frame__];
	return $dialog;
}

sub window {
	local('$dialog $4');
        $dialog = [new JFrame: $1];
	[$dialog setIconImage: [ImageIO read: resource("resources/armitage-icon.gif")]];

	fork({
		[$dialog addWindowListener: {
			if ($0 eq "windowClosing") {
				[$__frame__ closeConnect];
			}
		}];
	}, \$__frame__, \$dialog);

        [$dialog setSize: $2, $3];
        [$dialog setLayout: [new BorderLayout]];
	return $dialog;
}

# overlay_images(@("image.png", "image2.png", "..."))
#   constructs an image by overlaying all the specified images over eachother.
#   this function caches the result so each combination is only created once.
sub overlay_images {
	this('%cache');

	if (join(';', $1) in %cache) {
		return %cache[join(';', $1)];
	}

	local('$file $image $buffered $graphics $resource');

        $buffered = [new BufferedImage: 1000, 776, [BufferedImage TYPE_INT_ARGB]];
	$graphics = [$buffered createGraphics];
	foreach $file ($1) {
		$resource = resource($file);
		$image = [ImageIO read: $resource];
		closef($resource);
		[$graphics drawImage: $image, 0, 0, 1000, 776, $null];
	}

	$buffered = [$buffered getScaledInstance: 250 / $scale, 194 / $scale, [Image SCALE_SMOOTH]];

	%cache[join(';', $1)] = $buffered;
        return $buffered;
}

sub iconToImage {
	if ($1 isa ^ImageIcon) {
		return [$1 getImage];
	}
	else {
		local('$buffered $g');
	        $buffered = [new BufferedImage: [$1 getIconWidth], [$1 getIconHeight], [BufferedImage TYPE_INT_ARGB]];
		$g = [$buffered createGraphics];
		[$1 paintIcon: $null, $g, $2, $3];
		[$g dispose];
		return $buffered;
	}
}

sub imageToImage {
	local('$buffered $g');
        $buffered = [new BufferedImage: [$1 getWidth: $null], [$1 getHeight: $null], [BufferedImage TYPE_INT_ARGB]];
	$g = [$buffered createGraphics];
	[$g drawImage: $1, 0, 0, [$1 getWidth: $null], [$1 getHeight: $null], $null];
	[$g dispose];
	return $buffered;
}

sub select {
	local('$combo');
	$combo = [new JComboBox: cast($1, ^String)];
	[$combo setSelectedItem: $2];
	return $combo;
}

# buildTreeNodes(@)
sub buildTree {
	local('%nodes $entry $parent $path');

	foreach $entry ($1) {
		$parent = %nodes;
		foreach $path (split('\\/', $entry)) {
			if ($path !in $parent) {
				$parent[$path] = %();
			}
			$parent = $parent[$path];
		}
	}
	return %nodes;
}

# treeNodes($1, buildTree(@(...)))
sub treeNodes {
        local('$temp $p');

	if ($1 is $null) {
		$1 = [new DefaultMutableTreeNode: "modules"];
		[$1 setAllowsChildren: 1];
	}


	foreach $temp (sorta(keys($2))) {
		$p = [new DefaultMutableTreeNode: $temp];
		[$p setAllowsChildren: 1];

		if (size($2[$temp]) > 0) {
			treeNodes($p, $2[$temp]);
		}

		[$1 add: $p];
	}

	return $1;
}

sub wrapComponent {
	local('$panel');
	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];
	[$panel add: $1, [BorderLayout CENTER]];
	[$panel setBorder: [BorderFactory createEmptyBorder: $2, $2, $2, $2]];
	return $panel;
}

sub thread {
	local('$thread');
	$thread = [new ArmitageThread: $1];
	[$thread start];
}

sub compareHosts {
	if ($1 eq "unknown") {
		return compareHosts("0.0.0.0", $2);
	}
	else if ($2 eq "unknown") {
		return compareHosts($1, "0.0.0.0");
	}
	else {
		return [Route ipToLong: $1] <=> [Route ipToLong: $2];
	}
}

# tells table to save any edited cells before going forward...
sub syncTable {
	if ([$1 isEditing]) {
		[[$1 getCellEditor] stopCellEditing];
	}
}

sub isWindows {
	return iff("*Windows*" iswm systemProperties()["os.name"], 1);
}

sub selected {
	return [$2 getSelectedValueFromColumn: $1, $3];
}

# ($table, $model) = setupTable("lead", @rows)
sub setupTable {
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

# creates a list dialog,
# $1 = title, $2 = button text, $3 = columns, $4 = rows, $5 = callback
sub quickListDialog {
	local('$dialog $panel $table $row $model $button $sorter $after $a $tablef');
	$dialog = dialog($1, $width, $height);
	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];
	
	($table, $model) = setupTable($3[0], sublist($3, 1), $4);
	[$panel add: [new JScrollPane: $table], [BorderLayout CENTER]];

	if ($tablef !is $null) {
		[$tablef: $table, $model];
	}
	
	$button = [new JButton: $2];
	[$button addActionListener: lambda({
		[$callback : [$model getSelectedValueFromColumn: $table, $lead], $table, $model]; 
		[$dialog setVisible: 0];
	}, \$dialog, $callback => $5, \$model, \$table, $lead => $3[0])];

	local('$south');
	$south = [new JPanel];
        [$south setLayout: [new BoxLayout: $south, [BoxLayout Y_AXIS]]];

	if ($after !is $null) {
		foreach $a ($after) {
			[$south add: $a];
		}
	}
	[$south add: center($button)];

	[$panel add: $south, [BorderLayout SOUTH]];
	[$dialog add: $panel, [BorderLayout CENTER]];
	[$dialog show];
	[$dialog setVisible: 1];
}

sub setTableColumnWidths {
	local('$col $width $temp');
	foreach $col => $width ($2) {
		[[$1 getColumn: $col] setPreferredWidth: $width];
	}
}

sub tableRenderer {
	return [ATable getDefaultTableRenderer: $1, $2];
}

sub gotoFile {
	return lambda({
		local('$exception');
		try {
			if ([Desktop isDesktopSupported]) {
				[[Desktop getDesktop] open: $f];
			}
			else {
				ask("Browse to this file:", $f);
			}
		}
		catch $exception {
			showError("Could not open $f $+ \n $+ $exception");
		}
	}, $f => $1);
}

sub isShift {
	return iff(([$1 getModifiers] & [ActionEvent SHIFT_MASK]) == [ActionEvent SHIFT_MASK], 1);
}

inline safetyCheck {
	local('$__time');
	if ($__time == 0) {
		$__time = ticks();
	}
	if ((ticks() - $__time) > 250) {
		yield 50;
		$__time = ticks();
	}
}

sub addMouseListener {
	[$1 addMouseListener: [new SafeMouseListener: $2]];
}

sub pad {
	local('$panel');
	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];
	[$panel add: $1, [BorderLayout CENTER]];
	[$panel setBorder: [BorderFactory createEmptyBorder: $2, $3, $4, $5]];
	return $panel;
}

sub setClipboard {
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

sub setupMenu {
	[$frame setupMenu: $1, $2, _args($3)];
}

sub installMenu {
	[$frame installMenu: $1, $2, _args($3)];
}
