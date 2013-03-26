#
# Process Browser (for Meterpreter)
#

import table.*;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;
import ui.*;

sub createModuleBrowser {
	local('$tree $split $scroll1 $t');
	$split = [new JSplitPane: [JSplitPane HORIZONTAL_SPLIT], createModuleList(ohash(auxiliary => buildTree(@auxiliary), exploit => buildTree(@exploits), post => buildTree(@post), payload => buildTree(@payloads)), $2), iff($1, $1, [new JPanel])];
	[$split setOneTouchExpandable: 1];
	return $split;
}

sub isClientside {
	local('$options');
	$options = call($mclient, "module.options", "exploit", $1);
	return iff ('RHOST' in $options || 'RHOSTS' in $options, $null, 1);
}

sub showModulePopup {
	local('$event $type $path');
	($event, $type, $path) = @_;

	# we go through this hassle because &isClientside calls module.options which could block
	# and freeze the UI--we don't want to do that...
	thread(lambda(&_showModulePopup, \$event, \$type, \$path));
}

sub _showModulePopup {
	local('$menu');
	if (($type eq "exploit" && !isClientside($path)) || ($type eq "auxiliary" && "*_login" iswm $path)) {
		$menu = [new JPopupMenu];
		item($menu, "Relevant Targets", 'R', lambda({
			thread(lambda({
				local('$options %filter $os');
				$options = call($mclient, "module.options", $type, $module);
				
				if ("RPORT" in $options) {
					%filter["ports"] = $options['RPORT']['default'];

					if (%filter["ports"] eq '445') {
						%filter["ports"] .= ", 139";
					}
					else if (%filter["ports"] eq '80') {
						%filter["ports"] .= ", 443";
					}
				}

				$os = split('/', $module)[0];
				if ($os eq "windows") {
					%filter["os"] = "windows";
				}	
				else if ($os eq "linux") {
					%filter["os"] = "linux";
				}
				else if ($os eq "osx") {
					%filter["os"] = "ios, mac";
				}

				if (size(%filter) > 0) {
					thread(lambda({
						call($mclient, "db.filter", %filter);
					}, \%filter));
					[$frame setTitle: "$TITLE - $module"]
					showError("Created a dynamic workspace for this module.\nUse Workspaces -> Show All to see all hosts.");
				}
				else {
					showError("I'm sorry, this option doesn't work for\nthis module.");
				}
			}, \$module, \$type));
		}, $module => $path, \$type));

		setupMenu($menu, "module", @($type, $path));

		dispatchEvent(lambda({
			[$menu show: [$event getSource], [$event getX], [$event getY]];
		}, \$menu, \$event));
	}
	else {
		dispatchEvent(lambda({
			installMenu($event, "module", @($type, $path));
		}, \$type, \$path, \$event));
	}
}

sub moduleAction {
	local('$type $path $hosts');
	($type, $path, $hosts) = @_;

	thread(lambda({
		if ($path in @exploits || $path in @auxiliary || $path in @payloads || $path in @post) {
			if ($type eq "exploit") {
				if (isClientside($path) || $path eq "windows/local/current_user_psexec") {
					launch_dialog($path, $type, $path, 1, $hosts);
				}
				else {
					local('$a $b');
					$a = call($mclient, "module.info", "exploit", $path);
					$b = call($mclient, "module.options", "exploit", $path);
					dispatchEvent(lambda({
						attack_dialog($a, $b, $hosts, $path);
					}, \$a, \$b, \$hosts, \$path));
				}
			}
			else {
				launch_dialog($path, $type, $path, 1, $hosts);
			}
		}
	}, \$type, \$path, \$hosts));
}

sub createModuleList {
	local('$tree $split $scroll1 $t');
	$tree = [new ATree: treeNodes($null, $1)];
	[$tree setRootVisible: 0];
	[$tree setDragEnabled: 1];
	[$tree setTransferHandler: $2];

	addMouseListener($tree, lambda({
		local('$t');
		$t = [$1 isPopupTrigger];
		if ($t == 0 && ($0 ne "mousePressed" || [$1 getClickCount] < 2)) { 
			return;
		}

		local('$p');
		$p = [[$1 getSource] getPathForLocation: [$1 getX], [$1 getY]];
		if ($p is $null) {
			return;
		}
		else if ([$1 isPopupTrigger]) {
			local('$selected $type $path');
			$selected = map({ return "$1"; }, [$p getPath]);
			$type = $selected[1];
			$path = join('/', sublist($selected, 2));
			showModulePopup($1, $type, $path);
			return;
		}

		local('$selected $type $path $hosts');
		$selected = map({ return "$1"; }, [$p getPath]);
		if (size($selected) > 2) {
			$type = $selected[1];
			$path = join('/', sublist($selected, 2));
			$hosts = [$targets getSelectedHosts];
			moduleAction($type, $path, $hosts);
		}
	}));

	$scroll1 = [new JScrollPane: $tree, [JScrollPane VERTICAL_SCROLLBAR_AS_NEEDED], [JScrollPane HORIZONTAL_SCROLLBAR_AS_NEEDED]];

	local('$search $button');
	$search = [new ATextField: 10];
	[$search setToolTipText: "Enter a query to filter the MSF modules"];
	[$search addKeyListener: lambda({
		this('$id');

		if ($0 ne "keyReleased") {
			return;
		}

		local('$model $_id $text');
		$text = [$search getText];
		if ($text ne "" && strlen($text) >= 3) {
			local('$filter %list $a $e $p $o $x $f');
			$filter = lambda({ return iff(lc("* $+ $s $+ *") iswm lc($1), $1); }, $s => strrep($text, ' ', '*'));
			%list = ohash();
			$a = filter($filter, @auxiliary);
			$e = filter($filter, @exploits);
			$p = filter($filter, @payloads);
			$o = filter($filter, @post);
			if (size($a) > 0) { %list["auxiliary"] = buildTree($a); }
			if (size($e) > 0) { %list["exploit"] = buildTree($e); }
			if (size($p) > 0) { %list["payload"] = buildTree($p); }
			if (size($o) > 0) { %list["post"] = buildTree($o); }

			$_id = [(%list . "") hashCode];

			if ($id ne $_id) {
				$id = $_id;
				$model = treeNodes($null, %list);
				[[$tree getModel] setRoot: $model];
	
				for ($x = 0; $x < [$tree getRowCount]; $x++) {
					[$tree expandRow: $x];
				}
			}
		}
		else {
			$id = -1L;
			$model = treeNodes($null, $original);
			[[$tree getModel] setRoot: $model];
		}
	}, $original => $1, \$tree, \$search)];
	
	local('$panel');
	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];

	[$panel add: $scroll1, [BorderLayout CENTER]];
	[$panel add: wrapComponent($search, 5), [BorderLayout SOUTH]];

	[$panel setPreferredSize: [new Dimension: 180, 600] ];
	[$panel setMinimumSize: [new Dimension: 180, 0]];

	let(&showPostModules, \$tree, \$search)
	let(&showModules, \$tree, \$search)
	return $panel;
}

# shows the post modules compatible with a session... for this to work, the
# code that creates the module browser must call: let(&showExploitModules, $tree => ..., $search => ...)
sub showModules {
	local('%list $model $1 $2 $3 $4');

	%list = ohash(
			auxiliary => iff($1, buildTree($1), $null), 
			exploit => iff($2, buildTree($2), $null),
			payload => iff($3, buildTree($3), $null),
			post => iff($4, buildTree($4), $null));
	$model = treeNodes($null, %list);

	dispatchEvent(lambda({
		local('$x');
		[[$tree getModel] setRoot: $model];

		for ($x = 0; $x < [$tree getRowCount]; $x++) {
			[$tree expandRow: $x];
		}
		[$search setText: ""];
	}, \$search, \$tree, \$model));
}

sub showExploitModules {
	local('%list $model');
	if (size($1) == 0) {
		return;
	}

	showModules($null, $1, $null, $null);
}

# shows the post modules compatible with a session... for this to work, the
# code that creates the module browser must call: let(&showPostModules, $tree => ..., $search => ...)
sub showPostModules {
	local('@allowed $2 $3');
	@allowed = getOS(sessionToOS($1));
	fork({
		local('$modules %list $model');
		$modules = call($client, "session.compatible_modules", $sid)["modules"];
		$modules = map({ return substr($1, 5); }, $modules);

		# filter out operating systems.
		$modules = filter(lambda({ 
			local('$o');
			($o) = split('/', $1);
			return iff($o in @allowed, $1);		
		}, \@allowed), $modules);

		# filter out other stuff if a filter exists...
		if ($filter !is $null) {
			$modules = filter(lambda({ return iff($filter iswm $1, $1); }, \$filter), $modules);
		}

		if ($base is $null) {
			%list = ohash(post => buildTree($modules));
		}
		else {
			%list = $base;
			%list['post'] = buildTree($modules);
		}
		$model = treeNodes($null, %list);

		dispatchEvent(lambda({
			local('$x');
			[[$tree getModel] setRoot: $model];

			for ($x = 0; $x < [$tree getRowCount]; $x++) {
				[$tree expandRow: $x];
			}
			[$search setText: ""];
		}, \$search, \$tree, \$model));
	}, \$tree, \$search, $sid => $1, \$client, \@allowed, $filter => $2, $base => $3);
}

sub createModuleBrowserTab {
	[$frame addTab: "Modules", createModuleBrowser(), $null];
}
