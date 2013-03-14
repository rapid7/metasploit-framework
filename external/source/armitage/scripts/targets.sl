#
# this code handles the plumbing behind the nifty targets tab... user code can redefine any of these
# functions... so you can use what's here or build your own stuff. 
#

import msf.*;

import armitage.*;
import graph.*;
import table.*;

import javax.swing.*;
import javax.swing.event.*;

import java.awt.*;
import java.awt.event.*;

global('%hosts $targets');

sub getHostOS {
	return iff($1 in %hosts, %hosts[$1]['os_name'], $null);
}

sub getHostLabel {
	return iff($1 in %hosts, %hosts[$1]['label'], $null);
}

sub getSessions {
	return iff($1 in %hosts && 'sessions' in %hosts[$1], %hosts[$1]['sessions']);
}

sub sessionToOS {
	return getHostOS(sessionToHost($1));
}

sub sessionData {
	local('$host $data');
	foreach $host => $data (%hosts) {
		if ('sessions' in $data && $1 in $data['sessions']) {
			return $data['sessions'][$1];
		}
	}
	return $null;
}

sub sessionPlatform {
	local('$data');
	$data = sessionData($1);
	if ('platform' in $data) {
		return $data['platform'];
	}
	return $null;
}

sub sessionToHost {
	local('$host $data');
	foreach $host => $data (%hosts) {
		if ('sessions' in $data && $1 in $data['sessions']) {
			return $host;
		}
	}
	return $null;
}

on sessions {
	local('$address $key $session $data @routes @highlights $highlight $id $host $route $mask $peer %addr @nodes');
	$data = $1;
#	warn("&refreshSessions - $data");

	# clear all sessions from the hosts
	map({ $1['sessions'] = %(); }, values(%hosts));

	foreach $key => $session ($data) {
		$address = $session['session_host'];
		$peer    = split(':', $session['tunnel_peer'])[0];

		if ($address eq "") {
			$address = $session['target_host'];
		}

		if ($address eq "") {
			$address = $peer;
		}

		if ($address !in %hosts) {
			continue;
		}

		%hosts[$address]['sessions'][$key] = $session;
		%addr[$key] = $address;

		# add a highlight / route for a firewall / NAT device
		if ($peer ne $address && $peer ne "") {
			push(@routes, [new Route: $address, "255.255.255.255", $peer]);
			push(@highlights, @($peer, $address));
		}

		# save the route information related to this meterpreter session
		if ($session['routes'] ne "") {
			foreach $route (split(',', $session['routes'])) {
				($host, $mask) = split('/', $route);
				push(@routes, [new Route: $host, $mask, $address]);
			}
		}
	}

	# setup the highlighted edges
	foreach $route (@routes) {
		$gateway = [$route getGateway];
		foreach $key => $session ($data) {
			$host = %addr[$key];
			if ($gateway ne $host && [$route shouldRoute: $host]) {
				push(@highlights, @($gateway, $host));
			}
		}
	}

	# create a data structure with id, description, icon, and tooltip
	foreach $id => $host (%hosts) { 
		local('$tooltip');
		if ('os_match' in $host) {
			$tooltip = $host['os_match'];
		}
		else {
			$tooltip = "I know nothing about $id";
		}

		if ($host['show'] eq "1") {
			push(@nodes, @($id, $host['label'] . "", describeHost($host), showHost($host), $tooltip));
		}
	}

	[SwingUtilities invokeLater: let(&refreshGraph, \@routes, \@highlights, \@nodes)];
}

sub refreshGraph {
	local('$node $id $label $description $icons $tooltip $highlight');

	# update everything...
	[$graph start];
		# do the hosts?
		foreach $node (@nodes) {
			($id, $label, $description, $icons, $tooltip) = $node;
			[$graph addNode: $id, $label, $description, $icons, $tooltip];
		}

		# update the routes
		[$graph setRoutes: cast(@routes, ^Route)];

		foreach $highlight (@highlights) {
			[$graph highlightRoute: $highlight[0], $highlight[1]];
		}

		[$graph deleteNodes];
	[$graph end];
}

sub _refreshServices {
	local('$service $host $port');

	# clear all sessions from the hosts
	map({ $1['services'] = %(); }, values(%hosts));

	foreach $service ($1) {
		($host, $port) = values($service, @('host', 'port'));
		%hosts[$host]['services'][$port] = $service;
	}
}

on services {
	_refreshServices($1);
}

sub quickParse {
	if ($1 ismatch '.*? host=(.*?)(?:\s*service=.*?){0,1}\s*type=(.*?)\s+data=\\{(.*?)\\}') {
		local('$host $type $data %r $key $value');
		($host, $type, $data) = matched();
		%r = %(host => $host, type => $type);
		while ($data hasmatch ':([a-z_]+)\=\>"([^"]+)"') {
			($key, $value) = matched();
			%r[$key] = $value;
		}
		return %r;
	}
}

on hosts {
	local('$host $data $address %newh @fixes $key $value');
	$data = $1;
#	warn("&refreshHosts - $data");

	foreach $host ($data) {
		$address = $host['address'];
		if ($address in %hosts && size(%hosts[$address]) > 1) {
			%newh[$address] = %hosts[$address];

			# set the label to empty b/c team server won't add labels if there are no labels. This fixes
			# a corner case where a user might clear all labels and find they won't go away
			%newh[$address]['label'] = '';

			putAll(%newh[$address], keys($host), values($host));

			if ($host['os_name'] eq "") {
				%newh[$address]['os_name'] = "Unknown";
			}
			else {
				%newh[$address]['os_match'] = join(" ", values($host, @('os_name', 'os_flavor', 'os_sp')));
			}
		}
		else {
			$host['sessions'] = %();
			$host['services'] = %();
			%newh[$address] = $host;

			if ($host['os_name'] eq "" || $host['os_name'] eq "Unknown") {
				$host['os_name'] = "Unknown";
			}
			else {
				%newh[$address]['os_match'] = join(" ", values($host, @('os_name', 'os_flavor', 'os_sp')));
			}
		}

		# we saw this in our hosts, it's ok to show it in the viz.
		%newh[$address]['show'] = 1;
	}

	%hosts = %newh;
}

sub auto_layout_function {
	return lambda({
		[$graph setAutoLayout: $string];
		[$preferences setProperty: "graph.default_layout.layout", $string];
		savePreferences();
	}, $string => $1, $graph => $2);
}

sub graph_items {
	local('$a $b $c');

	setupMenu($1, "graph", @());

	$a = menu($1, 'Auto-Layout', 'A');
	item($a, 'Circle', 'C', auto_layout_function('circle', $2));
	item($a, 'Hierarchy', 'H', auto_layout_function('hierarchical', $2));
	item($a, 'Stack', 'S', auto_layout_function('stack', $2));
	separator($a);
	item($a, 'None', 'N', auto_layout_function('', $2));
	
	$b = menu($1, 'Layout', 'L');
	item($b, 'Circle', 'C', lambda({ [$graph doCircleLayout]; }, $graph => $2));
	item($b, 'Hierarchy', 'H', lambda({ [$graph doHierarchicalLayout]; }, $graph => $2));
	item($b, 'Stack', 'S', lambda({ [$graph doStackLayout]; }, $graph => $2));

	$c = menu($1, 'Zoom', 'Z');
	item($c, 'In', 'I', lambda({ [$graph zoom: 0.25]; }, $graph => $2));
	item($c, 'Out', 'O', lambda({ [$graph zoom: -0.25]; }, $graph => $2));
	separator($c);
	item($c, 'Reset', 'R', lambda({ [$graph resetZoom]; }, $graph => $2));
}

sub _importHosts {
	local('$console $success $file');
	$success = size($files);
	foreach $file ($files) {
		$file = '"' . $file . '"';
	}

	$console = createDisplayTab("Import", $file => "import");
	[$console addCommand: 'x', "db_import " . strrep(join(" ", $files), "\\", "\\\\")];
	[$console addListener: lambda({
		elog("imported hosts from $success file" . iff($success != 1, "s"));
	}, \$success)];
	[$console start];
	[$console stop];
}

# need to pass this function a $command local...
sub importHosts {
	local('$files $thread $closure');
	$files = iff(size(@_) > 0, @($1), chooseFile($multi => 1, $always => 1));
	if ($files is $null || size($files) == 0) {
		return;
	}

	# upload the files please...
	if ($client !is $mclient) {
		$closure = lambda(&_importHosts);
		$thread = [new ArmitageThread: $closure];

		fork({
			local('$file');
			foreach $file ($files) {
				$file = uploadBigFile($file);
			}
			$closure['$files'] = $files;
			[$thread start];
		}, \$mclient, \$files, \$thread, \$closure);
	}
	else {
		thread(lambda(&_importHosts, \$files));
	}
}

# setHostValueFunction(@hosts, varname, value)
#   returns a function that when called will update the metasploit database
sub setHostValueFunction {
	return lambda({
		local('$host %map $key $value');

		while (size(@args) >= 2) {
			($key, $value) = sublist(@args, 0, 2);
			%map[$key] = $value;
			shift(@args);
			shift(@args);
		}

		foreach $host (@hosts) {
			%map['host'] = $host;
			call_async($mclient, "db.report_host", %map);
		}
	}, @hosts => $1, @args => sublist(@_, 1));
}

sub clearHostFunction {
	return lambda({
		thread(lambda({
			local('@hosts2 $host @commands $queue');
			$queue = [new armitage.ConsoleQueue: $client];
			@hosts2 = copy(@hosts);
			while (size(@hosts2) > 0) {
				[$queue addCommand: $null, "hosts -d " . join(" ", sublist(@hosts2, 0, 20))];

				if (size(@hosts2) > 20) {
					@hosts2 = sublist(@hosts2, 20);
				}
				else {
					@hosts2 = @();
				}
			}

			[$queue addCommand: "x", "hosts -h"];
			[$queue addListener: lambda({
				elog("removed " . size(@hosts) . iff(size(@hosts) == 1, " host", " hosts"));
				[$queue stop];
			}, \@hosts, \$queue)];

			[$queue start];
		}, \@hosts));
	}, @hosts => $1);
}

sub clearDatabase {
	if (!askYesNo("This action will clear the database. You will lose all information\ncollected up to this point. You will not be able toget it back.\nWould you like to clear the database?", "Clear Database")) {
		elog("cleared the database");
		call_async($mclient, "db.clear");
	}
}

# called when a target is clicked on...
sub targetPopup {
        local('$popup');
        $popup = [new JPopupMenu];

        # no hosts are selected, create a menu related to the graph itself
        if (size($1) == 0 && [$preferences getProperty: "armitage.string.target_view", "graph"] eq "graph") {
		graph_items($popup, $graph);
		[$popup show: [$2 getSource], [$2 getX], [$2 getY]];
        }
        else if (size($1) > 0) {
		host_selected_items($popup, $1);
		[$popup show: [$2 getSource], [$2 getX], [$2 getY]];
        }
}

sub setDefaultAutoLayout {
	local('$type');
	$type = [$preferences getProperty: "graph.default_layout.layout", "circle"];
	[$1 setAutoLayout: $type];
}

sub makeScreenshot {
	local('$ss');
	
	if ($graph !is $null) {
		$ss = [$graph getScreenshot];

		if ($ss !is $null) {
			[javax.imageio.ImageIO write: $ss, "png", [new java.io.File: getFileProper($1)]];
			return getFileProper($1);
		}
	}
}

sub createDashboard {
	if ($targets !is $null) {
		[$targets actionPerformed: $null];
	}

	local('$graph %hosts $console $split $transfer');

	if ([$preferences getProperty: "armitage.string.target_view", "graph"] eq "graph") {
		setf('&overlay_images', lambda(&overlay_images, $scale => 1.0));
		$graph = [new NetworkGraph: $preferences];
	}
	else {
                setf('&overlay_images', lambda(&overlay_images, $scale => 11.0));
	        $graph = [new NetworkTable: $preferences];
	}

	# setup the drop portion of our drag and drop...
	$transfer = [new ui.ModuleTransferHandler];
	[$transfer setHandler: lambda({
		local('@temp $type $path $host');
		@temp = split('/', $1);
		$type = @temp[0];
		$path = join('/', sublist(@temp, 1));
		$host = [$graph getCellAt: $2];
		if ($host !is $null) {
			moduleAction($type, $path, @($host));
		}
	}, \$graph)];

	setDefaultAutoLayout($graph);

	[$frame setTop: createModuleBrowser($graph, $transfer)];

	$targets = $graph;
	[[$cortana getSharedData] put: "targets", $graph];
	[$targets setTransferHandler: $transfer];

	# now we can tell the scripting engine to start pulling data from metasploit...
	let(&refreshGraph, \$graph);

	[$graph setGraphPopup: lambda(&targetPopup, \$graph)];
	[$graph addActionForKeySetting: "graph.save_screenshot.shortcut", "ctrl pressed P", lambda({
		local('$location');
		$location = saveFile2($sel => "hosts.png");
		if ($location !is $null) {
			makeScreenshot($location);
		}
	}, \$graph)];

	let(&makeScreenshot, \$graph);
}
