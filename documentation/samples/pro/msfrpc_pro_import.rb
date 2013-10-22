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
  exit(1)
end

opts = {}

# Parse script-specific options
parser = Msf::RPC::Client.option_parser(opts)
parser.separator('Task Options:')

parser.on("--path PATH") do |path|
  opts[:path] = path
end

parser.on("--project PROJECT") do |project|
  opts[:project] = project
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

project 	= opts[:project] 	|| usage(parser)
path 		= opts[:path]		|| usage(parser)
user  		= @rpc.call("pro.default_admin_user")['username']
task 		= @rpc.call("pro.start_import", {
      'workspace'		=> project,
      'username' 		=> user,
      'DS_PATH'		=> path
})

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
