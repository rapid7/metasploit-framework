#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# This script lists each module with its references
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require 'rex'
require 'msf/ui'
require 'msf/base'
require 'uri'


# See lib/msf/core/module/reference.rb
# We gsub '#{in_ctx_val}' with the actual value
def types
  {
    'ALL'         => '',
    'CVE'         => 'http://cvedetails.com/cve/#{in_ctx_val}/',
    'CWE'         => 'http://cwe.mitre.org/data/definitions/#{in_ctx_val}.html',
    'BID'         => 'http://www.securityfocus.com/bid/#{in_ctx_val}',
    'MSB'         => 'http://technet.microsoft.com/en-us/security/bulletin/#{in_ctx_val}',
    'EDB'         => 'http://www.exploit-db.com/exploits/#{in_ctx_val}',
    'US-CERT-VU'  => 'http://www.kb.cert.org/vuls/id/#{in_ctx_val}',
    'ZDI'         => 'http://www.zerodayinitiative.com/advisories/ZDI-#{in_ctx_val}',
    'WPVDB'       => 'https://wpvulndb.com/vulnerabilities/#{in_ctx_val}',
    'PACKETSTORM' => 'https://packetstormsecurity.com/files/#{in_ctx_val}',
    'URL'         => '#{in_ctx_val}'
  }
end

STATUS_ALIVE       = 'Alive'
STATUS_DOWN        = 'Down'
STATUS_UNSUPPORTED = 'Unsupported'

sort         = 0
filter       = 'All'
filters      = ['all','exploit','payload','post','nop','encoder','auxiliary']
type         ='ALL'
match        = nil
check        = false
save         = nil
http_timeout = 20
$verbose     = false

opts = Rex::Parser::Arguments.new(
  "-h" => [ false, "Help menu." ],
  "-c" => [ false, "Check reference status"],
  "-s" => [ false, "Sort by Reference instead of Module Type."],
  "-r" => [ false, "Reverse Sort"],
  "-f" => [ true, "Filter based on Module Type [All,Exploit,Payload,Post,NOP,Encoder,Auxiliary] (Default = ALL)."],
  "-t" => [ true, "Type of Reference to sort by #{types.keys}"],
  "-x" => [ true, "String or RegEx to try and match against the Reference Field"],
  "-o" => [ true, "Save the results to a file"],
  "-i" => [ true, "Set an HTTP timeout"],
  "-v" => [ false, "Verbose"]
)

flags = []

opts.parse(ARGV) { |opt, idx, val|
  case opt
  when "-h"
    puts "\nMetasploit Script for Displaying Module Reference information."
    puts "=========================================================="
    puts opts.usage
    exit
  when "-c"
    flags << "URI Check: Yes"
    check = true
  when "-s"
    flags << "Order: Sorting by License"
    sort = 1
  when "-r"
    flags << "Order: Reverse Sorting"
    sort = 2
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
    unless types.has_key?(val)
      puts "Invalid Type Supplied: #{val}"
      puts "Please use one of these: #{types.keys.inspect}"
      exit
    end
    type = val
  when "-i"
    http_timeout = /^\d+/ === val ? val.to_i : 20
  when "-v"
    $verbose = true
  when "-x"
    flags << "Regex: #{val}"
    match = Regexp.new(val)
  when "-o"
    flags << "Output to file: Yes"
    save = val
  end
}

flags << "Type: #{type}"

puts flags * " | "

def get_ipv4_addr(hostname)
  Rex::Socket::getaddresses(hostname, false)[0]
end

def vprint_debug(msg='')
  print_debug(msg) if $verbose
end

def print_debug(msg='')
  $stderr.puts "[*] #{msg}"
end

def is_url_alive?(uri, http_timeout)
  print_debug("Checking: #{uri}")

  begin
    uri = URI(uri)
    rhost = get_ipv4_addr(uri.host)
  rescue SocketError, URI::InvalidURIError => e
    vprint_debug("#{e.message} in #is_url_alive?")
    return false
  end

  rport = uri.port || 80
  path  = uri.path.blank? ? '/' : uri.path
  vhost = rport == 80 ? uri.host : "#{uri.host}:#{rport}"
  if uri.scheme == 'https'
    cli = ::Rex::Proto::Http::Client.new(rhost, 443, {}, true, 'TLS1')
  else
    cli = ::Rex::Proto::Http::Client.new(rhost, rport)
  end

  begin
    cli.connect(http_timeout)
    req = cli.request_raw('uri'=>path, 'vhost'=>vhost)
    res = cli.send_recv(req, http_timeout)
  rescue Errno::ECONNRESET, Rex::ConnectionError, Rex::ConnectionRefused, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::UnsupportedProtocol, ::Timeout::Error, Errno::ETIMEDOUT => e
    vprint_debug("#{e.message} for #{uri}")
    return false
  ensure
    cli.close
  end

  if res.nil? || res.code == 404 || res.body =~ /<title>.*not found<\/title>/i
    vprint_debug("URI returned a not-found response: #{uri}")
    return false
  end

  vprint_debug("Good: #{uri}")

  true
end

def save_results(path, results)
  begin
    File.open(path, 'wb') do |f|
      f.write(results)
    end
    puts "Results saved to: #{path}"
  rescue Exception => e
    puts "Failed to save the file: #{e.message}"
  end
end

# Always disable the database (we never need it just to list module
# information).
framework_opts = { 'DisableDatabase' => true }

# If the user only wants a particular module type, no need to load the others
if filter.downcase != 'all'
  framework_opts[:module_types] = [ filter.downcase ]
end

# Initialize the simplified framework instance.
$framework = Msf::Simple::Framework.create(framework_opts)

if check
  columns = [ 'Module', 'Status', 'Reference' ]
else
  columns = [ 'Module', 'Reference' ]
end

tbl = Rex::Text::Table.new(
  'Header'  => 'Module References',
  'Indent'  => 2,
  'Columns' => columns
)

bad_refs_count  = 0

$framework.modules.each { |name, mod|
  if mod.nil?
    elog("module_reference.rb is unable to load #{name}")
    next
  end

  next if match and not name =~ match

  x = mod.new
  x.references.each do |r|
    ctx_id = r.ctx_id.upcase
    if type == 'ALL' || type == ctx_id

      if check
        if types.has_key?(ctx_id)
          uri = types[r.ctx_id.upcase].gsub(/\#{in_ctx_val}/, r.ctx_val)
          if is_url_alive?(uri, http_timeout)
            status = STATUS_ALIVE
          else
            bad_refs_count += 1
            status = STATUS_DOWN
          end
        else
          # The reference ID isn't supported so we don't know how to check this
          bad_refs_count += 1
          status = STATUS_UNSUPPORTED
        end
      end

      ref = "#{r.ctx_id}-#{r.ctx_val}"
      new_column = []
      new_column << x.fullname
      new_column << status if check
      new_column << ref
      tbl << new_column
    end
  end
}

if sort == 1
  tbl.sort_rows(1)
end


if sort == 2
  tbl.sort_rows(1)
  tbl.rows.reverse
end

puts
puts tbl.to_s
puts

puts "Number of bad references found: #{bad_refs_count}" if check
save_results(save, tbl.to_s) if save
