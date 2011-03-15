require 'rex/parser/nmap_xml'
require 'open3'

module Msf

###
#
# This module provides methods for interacting with nmap.
#
###

module Auxiliary::Nmap

attr_accessor :nmap_args, :nmap_bin, :nmap_log
attr_reader :nmap_pid

def initialize(info = {})
	super

	register_options([
		OptAddressRange.new('RHOSTS', [ true, "The target address range or CIDR identifier"]),
		OptBool.new('NMAP_VERBOSE', [ false, 'Display nmap output', true]),
		OptString.new('RPORTS', [ false, 'Ports to target']), # RPORT supersedes RPORTS
	], Auxiliary::Nmap)

	deregister_options("RPORT")
	@nmap_args = []
	@nmap_bin = nmap_binary_path
end

def vprint_status(msg='')
	return if not datastore['VERBOSE']
	print_status(msg)
end

def vprint_error(msg='')
	return if not datastore['VERBOSE']
	print_error(msg)
end

def vprint_good(msg='')
	return if not datastore['VERBOSE']
	print_good(msg)
end

def rports
	datastore['RPORTS']
end

def rport
	datastore['RPORT']
end

def set_nmap_cmd
	nmap_set_log
	nmap_add_ports
	nmap_cmd = [self.nmap_bin]
	self.nmap_args.unshift("-oX #{self.nmap_log[1]}")
	nmap_cmd << self.nmap_args.join(" ")
	nmap_cmd << datastore['RHOSTS']
	nmap_cmd.join(" ")
end

def nmap_build_args
	raise RuntimeError, "nmap_build_args() not defined by #{self.refname}"
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
	else
		raise RuntimeError, "Cannot locate the nmap binary"
	end
end

# Returns the [filehandle, pathname], and sets the same
# to self.nmap_log.
# Only supports XML format since that's the most useful.
def nmap_set_log
	outfile = Rex::Quickfile.new("msf3-nmap-")
	if Rex::Compat.is_cygwin and nmap_binary_path =~ /cygdrive/i
		outfile_path = Rex::Compat.cygwin_to_win32(nmap_outfile.path)
	else
		outfile_path = outfile.path
	end
	self.nmap_log = [outfile,outfile_path]
end

def nmap_show_args
	print_status self.nmap_args.join(" ")
end

def nmap_append_arg(str)
	if validate_nmap(str)
		self.nmap_args << str
	end
end

def nmap_reset_args
	self.nmap_args = []
end

# A helper to add in rport or rports as a -p argument
def nmap_add_ports
	if not nmap_validate_rports
		raise RuntimeError, "Cannot continue without a valid port list."
	end
	port_arg = "-p \"#{datastore['RPORT'] || rports}\""
	if nmap_validate_arg(port_arg) 
		self.nmap_args << port_arg
	else
		raise RunTimeError, "Argument is invalid"
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
	if datastore['RPORT'] && (datastore['RPORT'].kind_of?(Fixnum) || !datastore['RPORT'].empty?)
		return true
	end
	bad_port = false
	if rports.nil? || rports.empty?
		print_error "Missing RPORTS"
		return false
	end
	rports.split(/\s*,\s*/).each do |r|
		if r =~ /^([TU]:)?[0-9]*-?[0-9]*$/
			next
		else
			bad_port = true
			break
		end
	end
	if bad_port
		print_error "Malformed nmap port: #{r}"
		return false
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
		print_error "Malformed nmap arguments (contains '#{c}'): #{str}"
		return false 
	end
	# Check for commas outside of quoted arguments
	quoted_22 = /\x22[^\x22]*\x22/
	requoted_str = str.gsub(/'/,"\"")
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
	print_status "Nmap: processing hosts from #{self.nmap_log[1]}..."
	fh = self.nmap_log[0]
	nmap_data = fh.read(fh.stat.size)
	# fh.unlink
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
end

