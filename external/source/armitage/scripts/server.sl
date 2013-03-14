#
# -= Armitage Network Attack Collaboration Server =-
#
# This is a separate application. It creates a second interface that Armitage uses
# to collaborate with other network attack clients.
# 
# Features include:
# - Meterpreter multiplexing (writes take ownership of a session, reads are silently ignored
#   for non-owner clients).
# - Upload/download files (allows feature dependent on files to work)
# - Group chat (because everyone loves chatting...)
#
# This is a proof of concept quickly hacked out (do you see how long this code is?)
#
# My goal is to eventually see this technology ported to Metasploit's RPC interface
# so this second instance can be done away with.
#
# Any takers? :)
#

debug(7);

import msf.*;
import ssl.*;

sub result {
	local('$rv $key $value');
	$rv = [new HashMap];
	foreach $key => $value ($1) {
		[$rv put: "$key", "$value"];
	}
	return $rv;
}

sub event {
	local('$result');
	$result = formatDate("HH:mm:ss") . " $1";
	[$events put: $result];
}

sub client {
	local('$temp $result $method $eid $sid $args $data $session $index $rv $valid $h $channel $key $value $file $response $time $address $app $ver %async %consoles');

	# do these things asynchronously so we don't tie up a client's thread
	%async['module.execute'] = 1;
	%async['core.setg'] = 1;
	%async['console.destroy'] = 1;

	#
	# verify the client
	#
	$temp = readObject($handle);
	($method, $args) = $temp;
	if ($method ne "armitage.validate") {
		writeObject($handle, result(%(error => 1, message => "You're not authenticated")));
		[[$handle getOutputStream] flush];
		return;
	}
	else {
		local('$user $pass');
		($user, $pass, $eid, $app, $ver) = $args;

		if ($user ne $_user || $pass ne $_pass) {
			warn("Rejected $eid (invalid login)");
			writeObject($handle, result(%(error => 1, message => "Invalid login.")));
			[[$handle getOutputStream] flush];
			return;
		}
		else if ($app ne "armitage") {
			warn("Rejected $eid (wrong application)");
			writeObject($handle, result(%(error => 1, message => "Your client is not compatible with this server.\nPlease use the latest version of Armitage.")));
			[[$handle getOutputStream] flush];
			return;
		}
		else if ($ver < 120326) {
			warn("Rejected $eid (old software -- srsly, update people!)");
			writeObject($handle, result(%(error => 1, message => "Your client is outdated.\nPlease use the latest version of Armitage.")));
			[[$handle getOutputStream] flush];
			return;
		}
		else if ($motd ne "" && -exists $motd) {
			$temp = openf($motd);
			writeObject($handle, result(%(message => readb($temp, -1))));
			closef($temp);
		}
		else {
			writeObject($handle, result(%(message => "Collaboration setup!")));
		}

		if ($eid !is $null) {
			event("*** $eid joined\n");
			warn("*** $eid joined");
		}
		[[$handle getOutputStream] flush];
	}

	#
	# on our merry way processing it...
	#
	while $temp (readObject($handle)) {
		($method, $args) = $temp;

		if ($method eq "session.meterpreter_read") {
			($sid) = $args;
			$result = $null;

			acquire($read_lock);
				if (-isarray $queue[$sid] && size($queue[$sid]) > 0) {
					$result = shift($queue[$sid]);
				}
			release($read_lock);

			if ($result !is $null) {
				writeObject($handle, $result);
			}
			else {
				writeObject($handle, result(%(data => "", encoding => "base64")));
			}
		}
		else if ($method eq "session.meterpreter_write") {
			($sid, $data) = $args;

			#warn("P $sess_lock");
			acquire($sess_lock);
				$session = %sessions[$sid];
			release($sess_lock);
			#warn("V $sess_lock");

			if ($data ismatch "write -c (\\d+) (.*)\n") {
				($channel, $data) = matched();

				$file = getFileProper("command $+ $sid $+ . $+ $channel $+ .txt");
				$h = openf("> $+ $file");
				writeb($h, "$data $+ \r\n");
				closef($h);
				deleteOnExit($file);

				[$session addCommand: $id, "write -f \"" . strrep($file, "\\", "/") . "\" $channel $+ \n"];
			}
			else {
				[$session addCommand: $id, $data];
			}

			writeObject($handle, [new HashMap]);
		}
		else if ($method eq "armitage.lock") {
			($sid) = $args;
			acquire($lock_lock);
			$data = %locks[$sid];
			if ($data is $null) {
				%locks[$sid] = $eid;
			}
			release($lock_lock);
			if ($data is $null) {
				writeObject($handle, result(%()));
			}
			else {
				writeObject($handle, result(%(error => "$data owns this session.")));
			}
		}
		else if ($method eq "armitage.unlock") {
			($sid) = $args;
			acquire($lock_lock);
			$data = %locks[$sid];
			if ($data is $null || $data eq $eid) {
				%locks[$sid] = $null;
			}
			release($lock_lock);
			writeObject($handle, result(%()));
		}
		else if ($method eq "armitage.log") {
			($data, $address) = $args;
			event("* $eid $data $+ \n");
			if ($address is $null) {
				$address = [$client getLocalAddress];
			}
			call_async($client, "db.log_event", "$address $+ // $+ $eid", $data);
			writeObject($handle, result(%()));
		}
		else if ($method eq "armitage.skip") {
			[$events get: $eid];
			writeObject($handle, result(%()));
		}
		else if ($method eq "armitage.poll" || $method eq "armitage.push") {
			if ($method eq "armitage.push") {
				($null, $data) = $args;
				foreach $temp (split("\n", $data)) {
					[$events put: formatDate("HH:mm:ss") . " < $+ $[10]eid $+ > " . $data];
				}
			}

			$rv = result(%(data => [$events get: $eid], encoding => "base64", prompt => "$eid $+ > "));
			writeObject($handle, $rv);
		}
		else if ($method eq "armitage.lusers") {
			$rv = [new HashMap];
			[$rv put: "lusers", [$events clients]];
			writeObject($handle, $rv);
		}
		else if ($method eq "armitage.append") {
			($file, $data) = $args;

			$h = openf(">>" . getFileName($file));
			writeb($h, $data);
			closef($h);

			writeObject($handle, result(%()));
		}
		else if ($method eq "armitage.upload") {
			($file, $data) = $args;

			$h = openf(">" . getFileName($file));
			writeb($h, $data);
			closef($h);

			deleteOnExit(getFileName($file));

			writeObject($handle, result(%(file => getFileProper($file))));
		}
		else if ($method eq "armitage.download") {
			if (-exists $args[0] && -isFile $args[0]) {
				$h = openf($args[0]);
				$data = readb($h, -1);
				closef($h);
				writeObject($handle, result(%(data => $data)));
				deleteFile($args[0]);
			}
			else {
				writeObject($handle, result(%(error => "file does not exist")));
			}
		}
		else if ($method eq "armitage.download_nodelete") {
			if (-exists $args[0] && -isFile $args[0]) {
				$h = openf($args[0]);
				$data = readb($h, -1);
				closef($h);
				writeObject($handle, result(%(data => $data)));
			}
			else {
				writeObject($handle, result(%(error => "file does not exist")));
			}
		}
		else if ($method eq "armitage.downloads") {
			$response = listDownloads("downloads");
			writeObject($handle, $response);
		}
		else if ($method eq "db.hosts" || $method eq "db.services" || $method eq "db.creds" || $method eq "session.list" || $method eq "db.loots") {
			$response = [$client_cache execute: $eid, $method, $null];
	
			if ($args !is $null && -isarray $args && size($args) == 1 && $args[0] == [armitage.ArmitageTimer dataIdentity: $response]) {
				writeObject($handle, %(nochange => 1));
			}
			else {
				writeObject($handle, $response);
			}
		}
		else if ("db.filter" eq $method) {
			[$client_cache setFilter: $eid, $args];
			writeObject($handle, %());			
		}
		else if ("module.*" iswm $method && size($args) == 0) {
			# never underestimate the power of caching to alleviate load.
			$response = $null;

			acquire($cach_lock);
			if ($method in %cache) {
				$response = %cache[$method];
			}
			release($cach_lock);

			if ($response is $null) {
				$response = [$client execute: $method];

				acquire($cach_lock);
				%cache[$method] = $response;
				release($cach_lock);
			}

			writeObject($handle, $response);
		}
		else if ($method eq "console.create" || $method eq "console.allocate") {
			$response = [$client execute: $method];
			$data = [$response get: 'id'];
			%consoles[$data] = 1;
			writeObject($handle, $response);
		}
		else if ($method eq "console.destroy" || $method eq "console.release") {
			%consoles[$args[0]] = $null;
			[$client execute_async: $method, cast($args, ^Object)];
			writeObject($handle, %());
		}
		else if ($method eq "module.execute" && $args[0] eq "payload") {
			$response = [$client execute: $method, cast($args, ^Object)];
			writeObject($handle, $response);
		}
		else if ($method eq "module.execute_direct") {
			$response = [$client execute: "module.execute", cast($args, ^Object)];
			writeObject($handle, $response);
		}
		else if ($method in %async) {
			if ($args) {
				[$client execute_async: $method, cast($args, ^Object)];
			}
			else {
				[$client execute_async: $method];
			}

			writeObject($handle, %());
		}
		else {
			if ($args) {
				$response = [$client execute: $method, cast($args, ^Object)];
			}
			else {
				$response = [$client execute: $method];
			}

			writeObject($handle, $response);
		}
		[[$handle getOutputStream] flush];
	}

	if ($eid !is $null) {
		event("*** $eid left.\n");
		[$events free: $eid];
	}

	# reset the user's filter...
	[$client_cache setFilter: $eid, $null];

	# cleanup any locked sessions.
	acquire($lock_lock);
	foreach $key => $value (%locks) {
		if ($value eq $eid) {
			remove();
		}
	}
	release($lock_lock);

	# cleanup any consoles created by not let go of.
	foreach $key => $value (%consoles) {
		[$client execute_async: "console.release", cast(@("$key"), ^Object)];
	}
}

sub main {
	global('$client $mclient');
	local('$server %sessions $sess_lock $read_lock $lock_lock %locks %readq $id $error $auth %cache $cach_lock $client_cache $handle $console $events');

	$auth = unpack("H*", digest(rand() . ticks(), "MD5"))[0];

	#
	# chastise the user if they're wrong...
	#
	if (size(@ARGV) < 5) {
		println("Armitage deconfliction server requires the following arguments:
	armitage --server host port user pass 
		host  - the address of this host (where msfrpcd is running as well)
		port  - the port msfrpcd is listening on
		user  - the username for msfrpcd
		pass  - the password for msfprcd
		lport - [optional] port to bind the team server to");
		[System exit: 0];
	}
	
	local('$host $port $user $pass $sport');
	($host, $port, $user, $pass, $sport) = sublist(@_, 1);

	if ($sport is $null) {
		$sport = $port + 1;
	}

	#
	# some sanity checking
	#
	if ($host eq "127.0.0.1") {
		println("Do not specify 127.0.0.1 as your msfrpcd host. This IP address\nis given to clients and they use it to connect to this server.");
		[System exit: 0];
	}

	#
	# Connect to Metasploit's RPC Daemon
	#

	$client = [new MsgRpcImpl: $user, $pass, "127.0.0.1", long($port), $null, $null];
	while ($client is $null) {
		sleep(1000);
		$client = [new MsgRpcImpl: $user, $pass, "127.0.0.1", long($port), $null, $null];
	}
	$mclient = $client;
	initConsolePool(); # this needs to happen... right now.

	# we need this global to be set so our reverse listeners work as expected.
	$MY_ADDRESS = $host;

	#
	# setup the client cache
	#
	$client_cache = [new RpcCacheImpl: $client];

	#
	# This lock protects the %sessions variable
	#
	$sess_lock = semaphore(1);
	$read_lock = semaphore(1);
	$lock_lock = semaphore(1);
	$cach_lock = semaphore(1);

	# setup any shared buffers...
	$events    = [new armitage.ArmitageBuffer: 250];

	# set the LHOST to whatever the user specified (use console.write to make the string not UTF-8)
	$console = createConsole($client);
	call($client, "console.write", $console, "setg LHOST $host $+ \n");
	sleep(2000);
		# absorb the output of this command which is LHOST => ...
	call($client, "console.read", $console);

	# update server's understanding of this value...
	call($client, "armitage.set_ip", $host);

	#
	# create a thread to push console messages to the event queue for all clients.
	#
	fork({
		global('$r');
		while (1) {
			sleep(2000);
			$r = call($client, "console.read", $console);
			if ($r["data"] ne "") {
				[$events put: formatDate("HH:mm:ss") . " " . $r["data"]];
			}
		}
	}, \$client, \$events, \$console);

	#
	# Create a shared hash that contains a thread for each session...
	#
	%sessions = ohash();
	wait(fork({
		setMissPolicy(%sessions, { 
			warn("Creating a thread for $2");
			local('$session');
			$session = [new MeterpreterSession: $client, $2, 0]; 
			[$session addListener: lambda({
				if ($0 eq "commandTimeout" || $2 is $null) {
					return;
				}

				acquire($read_lock);

				# $2 = string id of handle, $1 = sid
				if (%readq[$2][$1] is $null) {
					%readq[$2][$1] = @();
				}

				#warn("Pushing into $2 -> $1 's read queue");
				#println([$3 get: "data"]);
				push(%readq[$2][$1], $3); 
				release($read_lock);
			})];
			return $session;
		});
	}, \%sessions, \$client, \%readq, \$read_lock));

	#
	# get base directory
	#
	setupBaseDirectory();

	#
	# setup the database
	# 
	checkError($null); # clear the error status...
	local('$database $error');
	$database = connectToDatabase();
	[$client setDatabase: $database]; 

	if (checkError($error)) {

		println("
** Error ** ** Error ** ** Error ** ** Error ** ** Error **

Could not connect to the Metasploit database. It's possible
that it's not running. Follow the database troubleshooting
steps at:

http://www.fastandeasyhacking.com/start

Also note: the latest Metasploit installer (4.1.4+) does not 
create a postgres start script for you. This would explain
why Metasploit's database isn't running. To create one, put:

exec $BASE_DIRECTORY $+ /postgresql/scripts/ctl.sh \"\$@\"

in /etc/init.d/framework-postgres. Then start the database:

service framework-postgres start");
		[System exit: 0];
	}

	# setup the reporting API (must happen after base directory/database is setup)
	initReporting();

	$server = [new SecureServerSocket: int($sport)];
	if (checkError($error)) {
		println("[-] Could not listen on $sport $+ : $error");
		[System exit: 0];
	}

	#
	# spit out the details
	#
	println("Use the following connection details to connect your clients:");
	println("\tHost: $host");
	println("\tPort: $sport");
	println("\tUser: $user");
	println("\tPass: $pass");
	println("\n\tFingerprint (check for this string when you connect):\n\t" . [$server fingerprint]);
	println("\n" . rand(@("I'm ready to accept you or other clients for who they are",
		"multi-player metasploit... ready to go",
		"hacking is such a lonely thing, until now",
		"feel free to connect now, Armitage is ready for collaboration")));

	$id = 0;

	while (1) {
		$handle = [$server accept];
		if ($handle !is $null) {
			%readq[$id] = %();
			fork(&client, \$client, \$handle, \%sessions, \$read_lock, \$sess_lock, $queue => %readq[$id], \$id, \$events, \$auth, \%locks, \$lock_lock, \$cach_lock, \%cache, \$motd, \$client_cache, $_user => $user, $_pass => $pass);

			$id++;
		}
	}
}

invoke(&main, @ARGV);
