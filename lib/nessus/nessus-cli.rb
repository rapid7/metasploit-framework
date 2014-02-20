#!/usr/bin/env ruby
# = nessus-cli.rb:  Nessus command line interface for XML-RPC
# Author:: Vlatko Kosturjak
# 
# (C) Vlatko Kosturjak, Kost. Distributed under GPL and BSD (dual licensed).

require 'nessus-xmlrpc'
require 'getoptlong'

verbose = 0
debug = 0
operation = ''
targets = ''
deletereport = false
user = ''
password = ''
scanname = ''
output = ''
output1 = ''
wait = ''
policy = ''
url = ''

def intro 
  $stderr.print $0 + ": Nessus command line interface for XML-RPC\n"
  $stderr.print "(C) Vlatko Kosturjak, Kost. Distributed under GPL.\n"
  $stderr.print "\n"
end

intro

def give_help
  puts <<-EOF
--user <user>	user for login to Nessus server
--password <p>	password for login to Nessus server
--scan <name>	start scan with name
--target <ip>	specify list of targets, separated by comma
--policy <pol>	specify policy to use (name of policy)
--url <url>	url of Nessus server (default: localhost:8834)
--wait [t]	wait scan to finish (ask in regular periods of <t> for status)
--output <f>	output report XML to file <f>
--output1 <f>	output report XML v1 to file <f>
--reportdelete	delete report after finish or delete report by id (if alone)
--stop <id>	stop scan identified by <id>
--stop-all	stop all scans
--pause <id>	pause scan identified by <id>
--pause-all	pause all scans
--resume <id>	resume scan identified by <id>
--resume-all	resume all scans
--report <id>	download report identified by <id>
--list-scans	list scans
--list-policy	list policies
--status <id>	get status of scan by <id>
--verbose	be verbose
--debug		be even more verbose
--help		this help

Examples: 
#{$0} --user john --password doe --scan scan-localhost --wait --output report.xml --target localhost
EOF
  exit 0
end

if ARGV.length < 1
  give_help
end

opt = GetoptLong.new(
  ["--help", "-h", GetoptLong::NO_ARGUMENT],
  ["--verbose", "-v", GetoptLong::OPTIONAL_ARGUMENT],
  ["--target", "-t", GetoptLong::REQUIRED_ARGUMENT],
  ["--user", "-u", GetoptLong::REQUIRED_ARGUMENT],
  ["--password", "-p", GetoptLong::REQUIRED_ARGUMENT],
  ["--policy", "-P", GetoptLong::REQUIRED_ARGUMENT],
  ["--url", "-U", GetoptLong::REQUIRED_ARGUMENT],
  ["--deletereport", "-D", GetoptLong::OPTIONAL_ARGUMENT],
  ["--wait", "-w", GetoptLong::OPTIONAL_ARGUMENT],
  ["--scan", "-s", GetoptLong::REQUIRED_ARGUMENT],
  ["--list-scans", "-l", GetoptLong::NO_ARGUMENT],
  ["--list-policy", "-L", GetoptLong::NO_ARGUMENT],
  ["--status", "-W", GetoptLong::REQUIRED_ARGUMENT],
  ["--stop", "-S", GetoptLong::REQUIRED_ARGUMENT],
  ["--stop-all", "-a", GetoptLong::NO_ARGUMENT],
  ["--pause", "-q", GetoptLong::REQUIRED_ARGUMENT],
  ["--pause-all", "-Q", GetoptLong::NO_ARGUMENT],
  ["--resume", "-e", GetoptLong::REQUIRED_ARGUMENT],
  ["--resume-all", "-E", GetoptLong::NO_ARGUMENT],
  ["--report", "-r", GetoptLong::REQUIRED_ARGUMENT],
  ["--output", "-o", GetoptLong::REQUIRED_ARGUMENT],
  ["--output1", "-1", GetoptLong::REQUIRED_ARGUMENT]
)

def give_error
  $stderr.print "You used incompatible options, probably you mixed --scan with --stop"
  $stderr.print "or something similar."
  exit 0
end

opt.each do |opt,arg|
  case opt
    when	'--help'
      give_help
    when	'--user'
      user = arg
    when	'--password'
      password = arg
    when 	'--stop'
      if operation == ''
        operation = "stop"
        scanname = arg
      else
        give_error
      end
    when 	'--pause'
      if operation == ''
        operation = "pause"
        scanname = arg
      else
        give_error
      end
    when 	'--resume'
      if operation == ''
        operation = "resume"
        scanname = arg
      else
        give_error
      end
    when 	'--stop-all'
      if operation == ''
        operation = "stop-all"
      else
        give_error
      end
    when 	'--pause-all'
      if operation == ''
        operation = "pause-all"
      else
        give_error
      end
    when 	'--resume-all'
      if operation == ''
        operation = "resume-all"
      else
        give_error
      end
    when 	'--report'
      if operation == ''
        operation = "report"
        scanname = arg
      else
        give_error
      end
    when 	'--scan'
      if operation == ''
        operation = "scan"
        scanname = arg
      else
        give_error
      end
    when	'--target'
      if arg[0..6] == 'file://'
        f = File.open(arg[7..-1], "r")
        f.each_line do |line|
          line=line.chomp
          line=line.strip
          unless line == '' or line == nil
            if targets == ''
              targets = line
            else
              targets = targets + "," + line
            end
          end
        end
        f.close
      else
        # if there's multiple target options, add comma
        if targets == ''
          targets = arg
          
        else
          targets = targets + "," + arg
        end
      end
    when	'--wait'
      if arg == ''
        wait = 15
      else
        wait = arg.to_i
      end
    when	'--reportdelete'
      if arg == ''
        deletereport=true
      else
        operation = "reportdelete"
        scanname = arg
      end

    when	'--output'
      output = arg
    when	'--output1'
      output1 = arg
    when	'--policy'
      policy = arg
    when	'--status'
      if operation == ''
        operation = "status"
        scanname = arg
      else
        give_error
      end
    when	'--url'
      url = arg
    when 	'--verbose'
      if arg == ''
        verbose += 1
      else
        verbose = arg.to_i
      end
    when 	'--debug'
      if arg == ''
        debug += 1
      else
        debug = arg.to_i
      end
    when	'--list-scans'
      if operation == ''
        operation = "list-scans"
        scanname = arg
      else
        give_error
      end
    when	'--list-policy'
      if operation == ''
        operation = "list-policy"
        scanname = arg
      else
        give_error
      end
  end
end

if (user == '') or (password == '')
  $stderr.print "User and password is required to login to Nessus server"
  $stderr.print "Try --help!"
  exit 1
end 

$stderr.print "[i] Targets: " + targets +"\n" if verbose > 0 
$stderr.print "[i] Connecting to nessus server: " if verbose > 0 
n=NessusXMLRPC::NessusXMLRPC.new(url,user,password) 
if n.logged_in 
  $stderr.print "OK!\n" if verbose > 0
else
  $stderr.print "[e] Error connecting/logging to the server!\n" 
  exit 2
end

case operation
  when "scan"
    if policy == ''
      $stderr.print "[w] Policy not defined, using first served from the server\n"
      pid,name = n.policy_get_first
      $stderr.print "[w] using policy id " + pid + " with name " + name + "\n"
    else
      pid=n.policy_get_id(policy)
      if pid == ''
        $stderr.print "[e] policy doesn't exit: " + policy + "\n"
        exit 3
      end
    end	
    if targets == ''
      $stderr.print "[w] Targets not defined, using localhost as target\n"
      targets = '127.0.0.1'
    end
    $stderr.print "[i] Initiating scan with targets: "+targets+': ' if verbose > 0
    uid=n.scan_new(pid,scanname,targets)
    $stderr.print "done\n" if verbose > 0
    unless wait == ''
      while not n.scan_finished(uid)
        $stderr.print "[v] Sleeping for " + wait.to_s() + ": " if verbose > 1			
        sleep wait
        $stderr.print "done\n" if verbose > 1
        stat = n.scan_status(uid)
        print "\r" + stat if verbose > 0
      end	
    else
      puts uid
      exit 0
    end	
    unless output == ''
      $stderr.print "[i] Output XML report to file: "+output if verbose > 0
      content=n.report_file_download(uid)	
      File.open(output, 'w') {|f| f.write(content) }	
      $stderr.print ": done\n" if verbose > 0
    end
    unless output1 == ''
      $stderr.print "[i] Output XML1 report to file: "+output1 if verbose > 0
      content=n.report_file1_download(uid)	
      File.open(output, 'w') {|f| f.write(content) }	
      $stderr.print ": done\n" if verbose > 0
    end
    if deletereport
      $stderr.print "[i] Deleting report: " if verbose > 0
      n.report_delete(uid)
      $stderr.print "done\n" if verbose > 0
    end
  when "report"
    uid=scanname
    if (output == '') and (output1 == '') 
      $stderr.print "[e] You want report, but specify filename with --output or output1\n"
    end
    unless output == ''
      $stderr.print "[i] Output XML report to file: "+output if verbose > 0
      content=n.report_file_download(uid)	
      File.open(output, 'w') {|f| f.write(content) }	
      $stderr.print ": done\n" if verbose > 0
    end
    unless output1 == ''
      $stderr.print "[i] Output XML1 report to file: "+output1 if verbose > 0
      content=n.report1_file_download(uid)	
      File.open(output, 'w') {|f| f.write(content) }	
      $stderr.print ": done\n" if verbose > 0
    end
    if deletereport
      $stderr.print "[i] Deleting report: " if verbose > 0
      n.report_delete(uid)
      $stderr.print "done\n" if verbose > 0
    end
  when "stop"
    $stderr.print "[i] Stopping scan: " + scanname if verbose > 0
    n.scan_stop(scanname)
    $stderr.print "done\n" if verbose > 0
  when "stop-all"
    $stderr.print "[i] Stopping all scans: " if verbose > 0	
    list=n.scan_stop_all
    $stderr.print "done\n" if verbose > 0
    if verbose > 1
      list.each {|uuid| puts "[v] Stop all: " + uuid }
    end
  when "pause"
    $stderr.print "[i] Pausing scan: " + scanname if verbose > 0
    n.scan_pause(scanname)
    $stderr.print "done\n" if verbose > 0
  when "pause-all"
    $stderr.print "[i] Pausing all scans: " if verbose > 0	
    list=n.scan_pause_all
    $stderr.print "done\n" if verbose > 0
    if verbose > 1
      list.each {|uuid| puts "[v] Pause all: " + uuid }
    end
  when "resume"
    $stderr.print "[i] Resuming scan: " + scanname if verbose > 0
    n.scan_resume(scanname)
    $stderr.print "done\n" if verbose > 0
  when "resume-all"
    $stderr.print "[i] Resuming all scans: " if verbose > 0	
    list=n.scan_resume_all
    $stderr.print "done\n" if verbose > 0
    if verbose > 1
      list.each {|uuid| puts "[v] Resume all: " + uuid }
    end
  when "reportdelete"
    $stderr.print "[i] Deleting report: " + scanname if verbose > 0
    n.report_delete(scanname)
    $stderr.print "done\n" if verbose > 0
  when "status"
    puts "status: " + n.scan_status(scanname)	
  when "list-scans"
    list=n.scan_list_hash
    list.each {|scan| 
      puts scan['id']+":"+scan['name']+":"+ \
        scan['current']+"/"+scan['total']
    }
  when "list-policy"
    list=n.policy_list_names
    list.each {|policy| 
      puts policy 
    }
    
end

$stderr.print "[v] End reached.\n" if verbose > 1
