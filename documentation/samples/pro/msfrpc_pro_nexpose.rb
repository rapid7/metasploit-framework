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
parser.separator('NeXpose Specific Options:')

parser.on("--project PROJECT") do |x|
  opts[:project] = x
end

parser.on("--targets TARGETS") do |x|
  opts[:targets] = [x]
end

parser.on("--nexpose-host HOST") do |x|
  opts[:nexpose_host] = x
end

parser.on("--nexpose-user USER") do |x|
  opts[:nexpose_user] = x
end

parser.on("--nexpose-pass PASSWORD") do |x|
  opts[:nexpose_pass] = x
end

parser.on("--nexpose-pass-file PATH") do |x|
  opts[:nexpose_pass_file] = x
end

parser.on("--scan-template TEMPLATE (optional)") do |x|
  opts[:scan_template] = x
end

parser.on("--nexpose-port PORT (optional)") do |x|
  opts[:nexpose_port] = x
end

parser.on("--blacklist BLACKLIST (optional)") do |x|
  opts[:blacklist] = x
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

# Get the password from the file
if opts[:nexpose_pass_file]
  nexpose_pass = File.open(opts[:nexpose_pass_file],"r").read.chomp!
else
  nexpose_pass = opts[:nexpose_pass] || usage(parser)
end

# Store the user's settings
project 			= opts[:project]		|| usage(parser),
targets 			= opts[:targets]		|| usage(parser),
blacklist			= opts[:blacklist],
nexpose_host			= opts[:nexpose_host] 		|| usage(parser),
nexpose_port			= opts[:nexpose_port]		|| "3780",
nexpose_user			= opts[:nexpose_user]		|| "nxadmin"
scan_template			= opts[:scan_template]		|| "pentest-audit"

# Get the default user
user   		= @rpc.call("pro.default_admin_user")['username']

options = {
        'workspace'			=> project,
        'username' 			=> user,
        'DS_WHITELIST_HOSTS'		=> targets,
        'DS_NEXPOSE_HOST'		=> nexpose_host,
        'DS_NEXPOSE_PORT'		=> nexpose_port,
        'DS_NEXPOSE_USER'		=> nexpose_user,
        'nexpose_pass'			=> nexpose_pass,
        'DS_SCAN_TEMPLATE'		=> scan_template
}

puts "DEBUG: Running task with #{options}"

# Create the task object with all options
task 		= @rpc.call("pro.start_exploit", options)


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
