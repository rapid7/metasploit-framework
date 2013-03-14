#
# Armitage Collaboration Feature... make no mistake, I'm extremely excited about this.
#

import msf.*;
import armitage.*;
import console.*;
import ssl.*;

sub createEventLogTab {
	this('$console $client');

	if ($client is $null && $console is $null) {
		$console = [new ActivityConsole: $preferences];
		setupEventStyle($console);
		logCheck($console, "all", "events");

		# define a menu for the eventlog
		[$console setPopupMenu: {
			installMenu($2, "eventlog", @());
		}];

		$client = [$cortana getEventLog: $console];
		[$client setEcho: $null];
		[$console updatePrompt: "> "];
		[new EventLogTabCompletion: $console, $mclient];
	}
	else {
		[$console updateProperties: $preferences];
	}

	[$frame addTab: "Event Log", $console, $null];
}

sub verify_server {
	this('%rejected');
	local('$fingerprints $fingerprint $check');
	$fingerprints = split(', ', [$preferences getProperty: "trusted.servers", ""]);
	foreach $fingerprint ($fingerprints) {
		if ($fingerprint eq $1) {
			return 1;
		}
	}

	if (%rejected[$1] == 1) {
		return $null;
	}

	$check = askYesNo("The team server's fingerprint is:\n\n<html><body><b> $+ $1 $+ </b></body></html>\n\nDoes this match the fingerprint shown\nwhen the team server started?", "Verify Fingerprint");

	if ($check) {
		%rejected[$1] = 1;
		return $null;
	}
	else {
		push($fingerprints, $1);
		[$preferences setProperty: "trusted.servers", join(", ", $fingerprints)];
		savePreferences();
		return 1;
	}
}

sub c_client {
	# run this thing in its own thread to avoid really stupid deadlock situations
	local('$handle');
	$handle = [[new SecureSocket: $1, int($2), &verify_server] client];
	push(@CLOSEME, $handle);
	return wait(fork({
		local('$client');
		$client = newInstance(^RpcConnection, lambda({
			writeObject($handle, @_);
			[[$handle getOutputStream] flush];
			return readObject($handle);
		}, \$handle));
		return [new RpcAsync: $client];
	}, \$handle));
}

sub userFingerprint {
	return unpack("H*", digest(values(systemProperties(), @("os.name", "user.home", "os.version")), "MD5"))[0];
}

sub setup_collaboration {
	local('$nick %r $mclient');
	
	$nick = ask("What is your nickname?");

	while (["$nick" trim] eq "") {
		$nick = ask("You can't use a blank nickname. What do you want?");
	}

	$mclient = c_client($3, $4);
	%r = call($mclient, "armitage.validate", $1, $2, $nick, "armitage", 120326);
	if (%r["error"] eq "1") {
		showErrorAndQuit(%r["message"]);
		return $null;
	}

	%r = call($client, "armitage.validate", $1, $2, $null, "armitage", 120326);
	$DESCRIBE = "$nick $+ @ $+ $3";
	return $mclient;
}

sub uploadFile {
	local('$handle %r $data');

	$handle = openf($1);
	$data = readb($handle, -1);
	closef($handle);

	%r = call($mclient, "armitage.upload", getFileName($1), $data);
	return %r['file'];
}

sub uploadBigFile {
	local('$handle %r $data $file $progress $total $sofar $time $start');

	$total = lof($1);
	$progress = [new javax.swing.ProgressMonitor: $null, "Upload " . getFileName($1), "Starting upload", 0, lof($1)];
	$start = ticks();
	$handle = openf($1);
	$data = readb($handle, 1024 * 256);
	%r = call($mclient, "armitage.upload", getFileName($1), $data);
	$sofar += strlen($data);

	while $data (readb($handle, 1024 * 256)) {
		$time = (ticks() - $start) / 1000.0;
		[$progress setProgress: $sofar];
		[$progress setNote: "Speed: " . round($sofar / $time) . " bytes/second"];
		call($mclient, "armitage.append", getFileName($1), $data);
		$sofar += strlen($data);
	}
	[$progress close];
	return %r['file'];
}

sub downloadFile {
	local('$file $handle %r $2');
	%r = call($mclient, "armitage.download", $1);
	$file = iff($2, $2, getFileName($1));	
	$handle = openf("> $+ $file");
	writeb($handle, %r['data']);
	closef($handle);
	return $file;
}

sub getFileContent {
	local('$file $handle %r');
	if ($mclient !is $client) {
		%r = call($mclient, "armitage.download_nodelete", $1);
		return %r['data'];
	}
	else {
		$handle = openf($1);
		$file = readb($handle, -1);
		closef($handle);
		return $file;
	}
}

# returns the folder where files should be downloaded to!
sub downloadDirectory {
	if ($client is $mclient) {
		local('@dirs $start $dir');
		$start = dataDirectory();
		push(@dirs, "downloads");
		addAll(@dirs, @_);
	
		foreach $dir (@dirs) {
			if (isWindows()) {
				$dir = strrep($dir, "/", "\\", ":", "");
			}
			$start = getFileProper($start, $dir);
		}
		return $start;
	}
	else {
		return "downloads/" . join("/", @_);
	}
}
