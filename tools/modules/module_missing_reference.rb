#!/usr/bin/env ruby

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end
$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))
$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require 'msfenv'
require 'msf/base'
require 'rex'

# See lib/msf/core/module/reference.rb
# We gsub '#{in_ctx_val}' with the actual value
def types
  [
    'ALL',
    'CVE',
    'CWE',
    'BID',
    'MSB',
    'EDB',
    'US-CERT-VU',
    'ZDI',
    'WPVDB',
    'PACKETSTORM',
    'URL'
  ]
end

filter  = 'All'
filters = ['all','exploit','payload','post','nop','encoder','auxiliary']
type    = 'CVE'
save    = nil

opts = Rex::Parser::Arguments.new(
  "-h" => [ false, "Help menu." ],
  "-f" => [ true, "Filter based on Module Type [All,Exploit,Payload,Post,NOP,Encoder,Auxiliary] (Default = ALL)."],
  "-t" => [ true, "Type of Reference to sort by #{types * ', '}"],
  "-o" => [ true, "Save the results to a file"]
)

flags = []

opts.parse(ARGV) { |opt, idx, val|
  case opt
  when "-h"
    puts "\nMetasploit Script for Displaying Missing References."
    puts "=========================================================="
    puts opts.usage
    exit
  when "-f"
    unless filters.include?(val.downcase)
      puts "Invalid Filter Supplied: #{val}"
      puts "Please use one of these: #{filters.map{|f|f.capitalize}.join(", ")}"
      exit
    end
    flags << "Module Filter: #{val}"
    filter = val
  when "-t"
    val = (val || '').upcase
    unless types.include?(val)
      puts "Invalid Type Supplied: #{val}"
      puts "Please use one of these: #{types.keys.inspect}"
      exit
    end
    type = val
  when "-o"
    flags << "Output to file: Yes"
    save = val
  end
}

flags << "Type: #{type}"

puts flags * " | "

framework_opts = { 'DisableDatabase' => true }
if filter.downcase != 'all'
  framework_opts[:module_types] = [ filter.downcase ]
end

$framework = Msf::Simple::Framework.create(framework_opts)

puts "[*] Going through Metasploit modules for missing #{type}..."

table = Rex::Text::Table.new(
    'Header'  => 'Missing Module References',
    'Indent'  => 2,
    'Columns' => ['Module', 'Missing Reference']
  )

$framework.modules.each { |name, mod|
  if mod.nil?
    elog("Unable to load #{name}")
    next
  end

  m = mod.new
  ref_ids = m.references.collect { |r| r.ctx_id }

  unless ref_ids.include?(type)
    puts "[*] Missing #{type} : #{m.fullname}"
    if save
      table << [m.fullname, type]
    end
  end
}

if save
  begin
    File.write(save, table.to_s)
    puts "[*] Results saved to: #{save}"
  rescue ::Exception
    puts "[*] Failed to save the results"
  end
end

