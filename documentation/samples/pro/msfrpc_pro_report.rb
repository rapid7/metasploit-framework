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

opts  = {
  :format => 'PDF'
}

parser = Msf::RPC::Client.option_parser(opts)

parser.separator('Report Options:')
parser.on("--format FORMAT") do |v|
  opts[:format] = v.upcase
end

parser.on("--project PROJECT") do |v|
  opts[:project] = v
end

parser.on("--output OUTFILE") do |v|
  opts[:output] = v
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

project = opts[:project] || usage(parser)
fname  = opts[:output]  || usage(parser)
rtype  = opts[:format]
user   = @rpc.call("pro.default_admin_user")['username']

task = @rpc.call("pro.start_report", {
      'DS_WHITELIST_HOSTS'        => "",
      'DS_BLACKLIST_HOSTS'        => "",
      'workspace'                 => project,
      'username'                  => user,
      'DS_MaskPasswords'          => false,
      'DS_IncludeTaskLog'         => false,
      'DS_JasperDisplaySession'   => true,
      'DS_JasperDisplayCharts'    => true,
      'DS_LootExcludeScreenshots' => false,
      'DS_LootExcludePasswords'   => false,
      'DS_JasperTemplate'         => "msfxv3.jrxml",
      'DS_REPORT_TYPE'            => rtype.upcase,
      'DS_UseJasper'              => true,
      'DS_UseCustomReporting'     => true,
      'DS_JasperProductName'      => "Metasploit Pro",
      'DS_JasperDbEnv'            => "production",
      'DS_JasperLogo'             => '',
      'DS_JasperDisplaySections'  => "1,2,3,4,5,6,7,8",
      'DS_EnablePCIReport'        => true,
      'DS_EnableFISMAReport'      => true,
      'DS_JasperDisplayWeb'       => true,
})


if not task['task_id']
  $stderr.puts "[-] Error generating the report: #{task.inspect}"
  exit(0)
end

puts "[*] Report is generating with Task ID #{task['task_id']}..."
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

report = @rpc.call('pro.report_download_by_task', task['task_id'])
if report and report['data']
  ::File.open(fname, "wb") do |fd|
    fd.write(report['data'])
  end
  $stderr.puts "[-] Report saved to #{::File.expand_path(fname)}"
else
  $stderr.puts "[-] Error downloading report: #{report.inspect}"
end

