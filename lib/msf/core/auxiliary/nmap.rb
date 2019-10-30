# -*- coding: binary -*-
require 'rex/parser/nmap_nokogiri'
require 'rex/parser/nmap_xml'
require 'open3'

module Msf

###
#
# This module provides methods for interacting with nmap.
# Modules that include this should define their own nmap_build_args()
# function, and usually should have some method for dealing with
# the data yielded from nmap_hosts(). See auxiliary/scanner/oracle/oracle_login
# for an example implementation.
#
###

module Auxiliary::Nmap

attr_accessor :nmap_args, :nmap_bin, :nmap_log
attr_reader :nmap_pid, :nmap_ver

def initialize(info = {})
  super

  register_options([
    Opt::RHOSTS,
    OptBool.new('NMAP_VERBOSE', [ false, 'Display nmap output', true]),
    OptString.new('RPORTS', [ false, 'Ports to target']), # RPORT supersedes RPORTS
  ], Auxiliary::Nmap)

  deregister_options("RPORT")
  @nmap_args = []
  @nmap_bin = nmap_binary_path
end

def rports
  datastore['RPORTS']
end

def rport
  datastore['RPORT']
end

def set_nmap_cmd
  self.nmap_bin || (raise "Cannot locate nmap binary")
  nmap_set_log
  nmap_add_ports
  nmap_cmd = [self.nmap_bin]
  self.nmap_args.unshift("-oX #{self.nmap_log[1]}")
  nmap_cmd << self.nmap_args.join(" ")
  nmap_cmd << datastore['RHOSTS']
  nmap_cmd.join(" ")
end

def get_nmap_ver
  self.nmap_bin || (raise "Cannot locate nmap binary")
  res = ""
  nmap_cmd = [self.nmap_bin]
  nmap_cmd << "--version"
  res << %x{#{nmap_cmd.join(" ")}} rescue nil
  res.gsub(/[\x0d\x0a]/n,"")
end

# Takes a version string in the form of Major.Minor and compares to
# the found version. It yells at you specifically if you try to
# compare a float b/c that's going to be a super common error.
# Comparing an Integer is okay, though.
def nmap_version_at_least?(test_ver=nil)
  raise ArgumentError, "Cannot compare a Float, use a String or Integer" if test_ver.kind_of? Float
  unless test_ver.to_s[/^([0-9]+(\x2e[0-9]+)?)/n]
    raise ArgumentError, "Bad Nmap comparison version: #{test_ver.inspect}"
  end
  test_ver_str = test_ver.to_s
  tnum_arr = $1.split(/\x2e/n)[0,2].map {|x| x.to_i}
  installed_ver = get_nmap_ver()
  vtag = installed_ver.split[2] # Should be ["Nmap", "version", "X.YZTAG", "(", "http..", ")"]
  return false if (vtag.nil? || vtag.empty?)
  return false unless (vtag =~ /^([0-9]+\x2e[0-9]+)/n) # Drop the tag.
  inum_arr = $1.split(/\x2e/n)[0,2].map {|x| x.to_i}
  return true if inum_arr[0] > tnum_arr[0]
  return false if inum_arr[0] < tnum_arr[0]
  inum_arr[1].to_i >= tnum_arr[1].to_i
end

def nmap_build_args
  raise "nmap_build_args() not defined by #{self.refname}"
end

def nmap_run
  nmap_cmd = set_nmap_cmd
  begin
    nmap_pipe = ::Open3::popen3(nmap_cmd)
    @nmap_pid = nmap_pipe.last.pid
    print_status "Nmap: Starting nmap with pid #{@nmap_pid}"
    temp_nmap_threads = []
    temp_nmap_threads << framework.threads.spawn("Module(#{self.refname})-NmapStdout", false, nmap_pipe[1]) do |np_1|
      np_1.each_line do |nmap_out|
        next if nmap_out.strip.empty?
        print_status "Nmap: #{nmap_out.strip}" if datastore['NMAP_VERBOSE']
      end
    end

    temp_nmap_threads << framework.threads.spawn("Module(#{self.refname})-NmapStderr", false, nmap_pipe[2]) do |np_2|
      np_2.each_line do |nmap_err|
        next if nmap_err.strip.empty?
        print_status  "Nmap: '#{nmap_err.strip}'"
      end
    end

    temp_nmap_threads.map {|t| t.join rescue nil}
    nmap_pipe.each {|p| p.close rescue nil}
    if self.nmap_log[0].size.zero?
      print_error "Nmap Warning: Output file is empty, no useful results can be processed."
    end
  rescue ::IOError
  end
end

def nmap_binary_path
  ret = Rex::FileUtils.find_full_path("nmap") || Rex::FileUtils.find_full_path("nmap.exe")
  if ret
    fullpath = ::File.expand_path(ret)
    if fullpath =~ /\s/ # Thanks, "Program Files"
      return "\"#{fullpath}\""
    else
      return fullpath
    end
  end
end

# Returns the [filehandle, pathname], and sets the same
# to self.nmap_log.
# Only supports XML format since that's the most useful.
def nmap_set_log
  outfile = Rex::Quickfile.new("msf3-nmap-")
  if Rex::Compat.is_cygwin and self.nmap_bin =~ /cygdrive/i
    outfile_path = Rex::Compat.cygwin_to_win32(outfile.path)
  else
    outfile_path = outfile.path
  end
  self.nmap_log = [outfile,outfile_path]
end

def nmap_show_args
  print_status self.nmap_args.join(" ")
end

def nmap_append_arg(str)
  if nmap_validate_arg(str)
    self.nmap_args << str
  end
end

def nmap_reset_args
  self.nmap_args = []
end

# A helper to add in rport or rports as a -p argument
def nmap_add_ports
  if not nmap_validate_rports
    raise "Cannot continue without a valid port list."
  end
  port_arg = "-p \"#{datastore['RPORT'] || rports}\""
  if nmap_validate_arg(port_arg)
    self.nmap_args << port_arg
  else
    raise "Argument is invalid"
  end
end

# Validates the correctness of ports passed to nmap's -p
# option. Note that this will not validate named ports (like
# 'http'), nor will it validate when brackets are specified.
# The acceptable formats for this is:
#
# 80
# 80-90
# 22,23
# U:53,T:80
# and combinations thereof.
def nmap_validate_rports
  # If there's an RPORT specified, use that instead.
  if datastore['RPORT'] && (datastore['RPORT'].kind_of?(Integer) || !datastore['RPORT'].empty?)
    return true
  end
  if rports.nil? || rports.empty?
    print_error "Missing RPORTS"
    return false
  end
  rports.split(/\s*,\s*/).each do |r|
    if r =~ /^([TU]:)?[0-9]*-?[0-9]*$/
      next
    else
      print_error "Malformed nmap port: #{r}"
      return false
    end
  end
  print_status "Using RPORTS range #{datastore['RPORTS']}"
  return true
end

# Validates an argument to be passed on the command
# line to nmap. Most special characters aren't allowed,
# and commas in arguments are only allowed inside a
# quoted argument.
def nmap_validate_arg(str)
  # Check for existence
  if str.nil? || str.empty?
    print_error "Missing nmap argument"
    return false
  end
  # Check for quote balance
  if !(str.scan(/'/).size % 2).zero? or !(str.scan(/"/).size % 2).zero?
    print_error "Unbalanced quotes in nmap argument: #{str}"
    return false
  end
  # Check for characters that enable badness
  disallowed_characters = /([\x00-\x19\x21\x23-\x26\x28\x29\x3b\x3e\x60\x7b\x7c\x7d\x7e-\xff])/n
  badchar = str[disallowed_characters]
  if badchar
    print_error "Malformed nmap arguments (contains '#{badchar}'): #{str}"
    return false
  end
  # Check for commas outside of quoted arguments
  quoted_22 = /\x22[^\x22]*\x22/n
  requoted_str = str.tr('\'','"')
  if requoted_str.split(quoted_22).join[/,/]
    print_error "Malformed nmap arguments (unquoted comma): #{str}"
    return false
  end
  return true
end

# Takes a block, and yields back the host object as discovered
# by the Rex::Parser::NmapXMLStreamParser. It's up to the
# module to ferret out whatever's interesting in this host
# object.
def nmap_hosts(&block)
  @nmap_bin || (raise "Cannot locate the nmap binary.")
  fh = self.nmap_log[0]
  nmap_data = fh.read(fh.stat.size)
  # fh.unlink
  if Rex::Parser.nokogiri_loaded && framework.db.active
    wspace = framework.db.find_workspace(datastore['WORKSPACE'])
    wspace ||= framework.db.workspace
    import_args = { :data => nmap_data, :wspace => wspace }
    framework.db.import_nmap_noko_stream(import_args) { |type, data| yield type, data }
  else
    nmap_parser = Rex::Parser::NmapXMLStreamParser.new
    nmap_parser.on_found_host = Proc.new { |h|
      if (h["addrs"].has_key?("ipv4"))
        addr = h["addrs"]["ipv4"]
      elsif (h["addrs"].has_key?("ipv6"))
        addr = h["addrs"]["ipv6"]
      else
        # Can't do much with it if it doesn't have an IP
        next
      end
      yield h
    }
    REXML::Document.parse_stream(nmap_data, nmap_parser)
  end
end

#Saves the data from the nmap scan to a file in the MSF::Config.local_directory
def nmap_save()
  print_status "Nmap: saving nmap log file"
  fh = self.nmap_log[0]
  nmap_data = fh.read(fh.stat.size)
  saved_path = store_local("nmap.scan.xml", "text/xml", nmap_data, "nmap_#{Time.now.utc.to_i}.xml")
  print_status "Saved NMAP XML results to #{saved_path}"
end

end
end

