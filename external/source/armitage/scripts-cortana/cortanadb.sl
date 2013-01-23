# This file is part of a stand-alone script environment that connects Cortana to 
# Metasploit, Armitage, and a postgresql database. It's a little complicated and
# twisty turny in here. Here are the rough steps:
#
# 1. Connect to the database (&main)
# 2. setup the default reverse handler (&setupHandlers)
# 3. check for the collaboration server (&checkForCollaborationServer)
# 4. setup collaboration (&setup_collaboration)
# 5. call armitage.skip to push the event log pointer to the very end.
# 6. send a flag back to the Cortana load that we're ready ([$loader passObject: ...])
#
# If any of these steps fails, Cortana will exit with a hopefully helpful error
# message.

debug(7 | 34);

import msf.*;
import armitage.*;
import console.*;
import ssl.*;

# create an RPC client for talking to the deconfliction server.
sub c_client {
	# run this thing in its own thread to avoid really stupid deadlock situations
	local('$handle');
	$handle = [[new SecureSocket: $1, int($2), $null] client];
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

# this function sets up a default meterpreter reverse handler on a random port. Better tha
# requiring the user to connect a client to make this happen. This function also fires the
# loader ready function which tells the script loader that this script is done processing
# and this Cortana container may continue loading and executing other scripts.
sub setupHandlers {
	find_job("Exploit: multi/handler", {
		if ($1 == -1) {
			# set LPORT for the user...
			local('$c');
			$c = call($client, "console.allocate")['id'];
			call($client, "console.write", $c, "setg LPORT " . randomPort() . "\n");
			call($client, "console.release", $c);

			# setup a handler for meterpreter
			call($client, "module.execute", "exploit", "multi/handler", %(
				PAYLOAD => "windows/meterpreter/reverse_tcp",
				LHOST => "0.0.0.0",
				ExitOnSession => "false"
			));
		}
	});
}

sub main {
	global('$client $mclient');
	local('%r $exception $lhost $temp $c');

	setField(^msf.MeterpreterSession, DEFAULT_WAIT => 20000L);

	try {
		# connect our first thread...
		$mclient = c_client($host, $port);

		# connect our second thread with an empty nickname
		$client = c_client($host, $port);
	}
	catch $exception {
		println("Could not connect to $host $+ : $+ $port ( $+ $exception $+ )");
		[System exit: 0];
	}

	# setup first thread...
	%r = call($mclient, "armitage.validate", $user, $pass, $nick, "armitage", 120326);
	if (%r["error"] eq "1") {
		println(%r['message']);
		[System exit: 0];
	}

	# setup second thread.
        %r = call($client, "armitage.validate", $user, $pass, $null, "armitage", 120326);

	# resolve lhost..
	$c = call($client, "console.allocate")['id'];
	call($client, "console.write", $c, "setg LHOST\n");
	while ($lhost eq "") {
		$temp = call($client, "console.read", $c)['data'];
		if (["$temp" startsWith: "LHOST => "]) {
			$lhost = substr(["$temp" trim], 9);
		}
		else {
			# this shouldn't happen because having LHOST set is a precondition
			# for Cortana to connect to a team server.
			sleep(1000);
		}
	}
	call($client, "console.release", $c);

	# pass some objects back yo.
	[$loader passObjects: $client, $mclient, $lhost];

	# don't make previous messages available...
	call($mclient, "armitage.skip");

	# do some other setup stuff...
	setupBaseDirectory();
	setupHandlers();
}

invoke(&main);
