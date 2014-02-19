#!/usr/bin/env ruby
require 'rubygems'
require 'optparse'
require 'msfrpc-client'
require 'rex/ui'

def usage(ropts)
  $stderr.puts ropts

  if @rpc and @rpc.token
    wspaces = @rpc.call("pro.workspaces") rescue {}
    if wspaces.keys.length > 0
      $stderr.puts "Active Projects:"
      wspaces.each_pair do |k,v|
        $stderr.puts "\t#{k}"
      end
    end
  end
  $stderr.puts ""
  exit(1)
end

opts = {}

# Parse script-specific options
parser = Msf::RPC::Client.option_parser(opts)
parser.separator('Discover Mandatory Options:')

parser.on("--project PROJECT") do |x|
  opts[:project] = x
end

parser.on("--targets TARGETS") do |x|
  opts[:targets] = [x]
end

parser.on("--blacklist BLACKLIST (optional)") do |x|
  opts[:blacklist] = x
end

parser.on("--speed SPEED (optional)") do |x|
  opts[:speed] = x
end

parser.on("--extra-ports PORTS (optional)") do |x|
  opts[:extra_ports] = x
end

parser.on("--blacklist-ports PORTS (optional)") do |x|
  opts[:blacklist_ports] = x
end

parser.on("--custom-ports PORTS (optional)") do |x|
  opts[:custom_ports] = x
end

parser.on("--portscan-timeout TIMEOUT (optional)") do |x|
  opts[:portscan_timeout] = x
end

parser.on("--source-port PORT (optional)") do |x|
  opts[:source_port] = x
end

parser.on("--custom-nmap-options OPTIONS (optional)") do |x|
  opts[:custom_nmap_options] = x
end

parser.on("--disable-udp-probes (optional)") do
  opts[:disable_udp_probes] = true
end

parser.on("--disable-finger-users (optional)") do
  opts[:disable_finger_users] = true
end

parser.on("--disable-snmp-scan (optional)") do 
  opts[:disable_snmp_scan] = true
end

parser.on("--disable-service-identification (optional)") do
  opts[:disable_service_identification] = true
end

parser.on("--smb-user USER (optional)") do |x|
  opts[:smb_user] = x
end

parser.on("--smb-pass PASS (optional)") do |x|
  opts[:smb_pass] = x
end

parser.on("--smb-domain DOMAIN (optional)") do |x|
  opts[:smb_domain] = x
end

parser.on("--dry-run (optional)") do
  opts[:dry_run] = true
end

parser.on("--single-scan (optional)") do
  opts[:single_scan] = true
end

parser.on("--fast-detect (optional)") do
  opts[:fast_detect] = true
end

parser.on("--help") do
  $stderr.puts parser
  exit(1)
end

parser.separator('')
parser.parse!(ARGV)

@rpc  = Msf::RPC::Client.new(opts)

if not @rpc.token
  $stderr.puts "Error: Invalid RPC server options specified"
  $stderr.puts parser
  exit(1)
end

# Provide default values for certain options - If there's no alternative set
# use the default provided by Pro -- see the documentation.
project 			= opts[:project]	|| usage(parser)
targets 			= opts[:targets]	|| usage(parser)
blacklist			= opts[:blacklist]
speed				= opts[:speed]		|| "5"
extra_ports			= opts[:extra_ports]
blacklist_ports			= opts[:blacklist_ports]
custom_ports			= opts[:custom_ports]
portscan_timeout		= opts[:portscan_timeout]	|| 300
source_port			= opts[:source_port]
custom_nmap_options		= opts[:custom_nmap_options] || 
disable_udp_probes		= opts[:disable_udp_probes] || false
disable_finger_users		= opts[:disable_finger_users] || false
disable_snmp_scan		= opts[:disable_snmp_scan] || false
disable_service_identification	= opts[:disable_service_identification] || false
smb_user			= opts[:smb_user] || ""
smb_pass			= opts[:smb_pass] || ""
smb_domain			= opts[:smb_domain] || ""
single_scan			= opts[:single_scan] || false
fast_detect			= opts[:fast_detect] || false

# Get the default user from Pro
user   		= @rpc.call("pro.default_admin_user")['username']

# Create the task object with all options
task 		= @rpc.call("pro.start_discover", {
        'workspace'		=> project,
        'username' 		=> user,
        'ips'			=> targets,
        'DS_BLACKLIST_HOSTS'	=> blacklist,
        'DS_PORTSCAN_SPEED'	=> speed,
        'DS_PORTS_EXTRA'	=> extra_ports,
        'DS_PORTS_BLACKLIST'	=> blacklist_ports,
        'DS_PORTS_CUSTOM'	=> custom_ports,
        'DS_PORTSCAN_TIMEOUT' 	=> portscan_timeout,
        'DS_PORTSCAN_SOURCE_PORT' => source_port,
        'DS_CustomNmap'		=> custom_nmap_options,
        'DS_UDP_PROBES'		=> disable_udp_probes,
        'DS_FINGER_USERS'	=> disable_finger_users,
        'DS_SNMP_SCAN'		=> disable_snmp_scan,
        'DS_IDENTIFY_SERVICES'	=> disable_service_identification,
        'DS_SMBUser'		=> smb_user,
        'DS_SMBPass'		=> smb_pass,
        'DS_SMBDomain'		=> smb_domain,
        'DS_SINGLE_SCAN'	=> single_scan, 
        'DS_FAST_DETECT'	=> fast_detect
})

puts "DEBUG: Running task with #{task.inspect}"

if not task['task_id']
  $stderr.puts "[-] Error starting the task: #{task.inspect}"
  exit(0)
end

puts "[*] Creating Task ID #{task['task_id']}..."
while true
  select(nil, nil, nil, 0.50)

  stat = @rpc.call("pro.task_status", task['task_id'])

  if stat['status'] == 'invalid'
    $stderr.puts "[-] Error checking task status"
    exit(0)
  end

  info = stat[ task['task_id'] ]

  if not info
    $stderr.puts "[-] Error finding the task"
    exit(0)
  end

  if info['status'] == "error"
    $stderr.puts "[-] Error generating report: #{info['error']}"
    exit(0)
  end

  break if info['progress'] == 100
end

$stdout.puts "[+] Task Complete!"
