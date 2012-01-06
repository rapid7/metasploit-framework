##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

	def initialize(info={})
		super(update_info(info,
			'Name'           => "Windows Gather Directory Permissions Enumeration",
			'Description'    => %q{
				This module enumerates directories and lists the permissions set
				on found directories.
			},
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision$',
			'Platform'       => ['windows'],
			'SessionTypes'   => ['meterpreter'],
			'Author'         => ['Kx499']
		))

		register_options(
			[
				OptString.new('PATH', [ true, 'Directory to begin search from', '']),
				OptEnum.new('FILTER', [ false, 'Filter to limit results by', 'NA', [ 'NA', 'R', 'W', 'RW' ]]),
				OptInt.new('DEPTH', [ true, 'Depth to drill down into subdirs, O = no limit',0]),
			], self.class)
	end

	def get_imperstoken
		adv =  session.railgun.advapi32
		tok_all = "TOKEN_ASSIGN_PRIMARY |TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | "
		tok_all << "TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS"
		tok_all << " | TOKEN_ADJUST_DEFAULT"

		#get impersonation token handle it["DuplicateTokenhandle"] carries this value
		#p = kern.GetCurrentProcess() #get handle to current process
		pid = session.sys.process.open.pid
		pr = session.sys.process.open(pid, PROCESS_ALL_ACCESS)
		pt = adv.OpenProcessToken(pr.handle, tok_all, 4) #get handle to primary token
		it = adv.DuplicateToken(pt["TokenHandle"],2, 4) # get an impersonation token
		if it["return"] #if it fails return 0 for error handling
			return it["DuplicateTokenHandle"]
		else
			return 0
		end
	end

	def check_dir(dir, token)
		# If path doesn't exist, do not continue
		begin
			session.fs.dir.entries(dir)
		rescue
			print_error("Path seems invalid: #{dir}")
			return nil
		end

		adv =  session.railgun.advapi32
		si = "OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION"
		result = ""

		#define generic mapping structure
		gen_map = [0,0,0,0]
		gen_map = gen_map.pack("L")

		#get Security Descriptor for the directory
		f = adv.GetFileSecurityA(dir, si, 20, 20, 4)
		f = adv.GetFileSecurityA(dir, si, f["lpnLengthNeeded"], f["lpnLengthNeeded"], 4)
		sd = f["pSecurityDescriptor"]

		#check for write access, called once to get buffer size
		a = adv.AccessCheck(sd, token, "ACCESS_READ | ACCESS_WRITE", gen_map, 0, 0, 4, 8)
		len = a["PrivilegeSetLength"]

		r = adv.AccessCheck(sd, token, "ACCESS_READ", gen_map, len, len, 4, 8)
		if !r["return"] then return nil end
		if r["GrantedAccess"] > 0 then result << "R" end

		w = adv.AccessCheck(sd, token, "ACCESS_WRITE", gen_map, len, len, 4, 8)
		if !w["return"] then return nil end
		if w["GrantedAccess"] > 0 then result << "W" end
	end

	def enum_subdirs(dpath, maxdepth, token)
		filter = datastore['FILTER']
		filter = nil if datastore['FILTER'] == 'NA'
		dirs = session.fs.dir.foreach(dpath)
		if maxdepth >= 1 or maxdepth < 0
			dirs.each do|d|
				next if d =~ /^(\.|\.\.)$/
				realpath = dpath + '\\' + d
				if session.fs.file.stat(realpath).directory?
					perm = check_dir(realpath, token)
					if !filter or perm.include? filter
						print_status(perm + "\t" + realpath)
					end
					enum_subdirs(realpath, maxdepth - 1,token)
				end
			end
		end
	end

	def run
		t = 0 #holds impers token

		#check and set vars
		if not datastore['PATH'].empty?
			path = datastore['PATH']
		end

		depth = -1

		if datastore['DEPTH'] > 0
			depth = datastore['DEPTH']
		end

		#get impersonation token
		print_status("Getting impersonation token...")
		t = get_imperstoken()

		#loop through sub dirs if we have an impers token..else error
		if t == 0
			print_error("Getting impersonation token failed")
		else
			print_status("Got token...")
			print_status("Checking directory permissions from: " + path)

			is_path_valid = check_dir(path, t)
			if not is_path_valid.nil?
				#call recursive function to loop through and check all sub directories
				enum_subdirs(path, depth, t)
			end
		end
	end
end
