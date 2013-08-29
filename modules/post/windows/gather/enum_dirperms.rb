##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Post

	def initialize(info={})
		super(update_info(info,
			'Name'           => "Windows Gather Directory Permissions Enumeration",
			'Description'    => %q{
				This module enumerates directories and lists the permissions set
				on found directories. Please note: if the PATH option isn't specified,
				then the module will start enumerate whatever is in the target machine's
				%PATH% variable.
			},
			'License'        => MSF_LICENSE,
			'Platform'       => ['win'],
			'SessionTypes'   => ['meterpreter'],
			'Author'         =>
				[
					'Kx499',
					'Ben Campbell <eat_meatballs[at]hotmail.co.uk>',
					'sinn3r'
				]
		))

		register_options(
			[
				OptString.new('PATH', [ false, 'Directory to begin search from', '']),
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
		rescue => e
			vprint_error("#{e.message}: #{dir}")
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

	def enum_subdirs(perm_filter, dpath, maxdepth, token)
		filter = datastore['FILTER']
		filter = nil if datastore['FILTER'] == 'NA'

		begin
			dirs = session.fs.dir.foreach(dpath)
		rescue Rex::Post::Meterpreter::RequestError
			# Sometimes we cannot see the dir
			dirs = []
		end

		if maxdepth >= 1 or maxdepth < 0
			dirs.each do|d|
				next if d =~ /^(\.|\.\.)$/
				realpath = dpath + '\\' + d
				if session.fs.file.stat(realpath).directory?
					perm = check_dir(realpath, token)
					if perm_filter and perm and perm.include?(perm_filter)
						print_status(perm + "\t" + realpath)
					end
					enum_subdirs(perm_filter, realpath, maxdepth - 1,token)
				end
			end
		end
	end

	def get_paths
		p = datastore['PATH']
		return [p] if not p.nil? and not p.empty?

		begin
			p = cmd_exec("cmd.exe", "/c echo %PATH%")
		rescue Rex::Post::Meterpreter::RequestError => e
			vprint_error(e.message)
			return []
		end
		print_status("Option 'PATH' isn't specified. Using system %PATH%")
		if p.include?(';')
			return p.split(';')
		else
			return [p]
		end
	end

	def get_token
		print_status("Getting impersonation token...")
		begin
			t = get_imperstoken()
		rescue ::Exception => e
			# Failure due to timeout, access denied, etc.
			t = 0
			vprint_error("Error #{e.message} while using get_imperstoken()")
			vprint_error(e.backtrace)
		end
		return t
	end

	def enum_perms(perm_filter, token, depth, paths)
		paths.each do |path|
			next if path.empty?
			path = path.strip

			print_status("Checking directory permissions from: #{path}")

			perm = check_dir(path, token)
			if not perm.nil?
				# Show the permission of the parent directory
				if perm_filter and perm.include?(perm_filter)
					print_status(perm + "\t" + path)
				end

				#call recursive function to loop through and check all sub directories
				enum_subdirs(perm_filter, path, depth, token)
			end
		end
	end

	def run
		perm_filter = datastore['FILTER']
		perm_filter = nil if datastore['FILTER'] == 'NA'

		paths = get_paths
		if paths.empty?
			print_error("Unable to get the path")
			return
		end

		depth = -1
		if datastore['DEPTH'] > 0
			depth = datastore['DEPTH']
		end

		t = get_token

		if t == 0
			print_error("Getting impersonation token failed")
		else
			print_status("Got token: #{t.to_s}...")
			enum_perms(perm_filter, t, depth, paths)
		end
	end
end
