require 'msf/core/post/windows/registry'

module Msf
class Post
module Windows

module UserProfiles
	include Msf::Post::Windows::Registry
	
	def grab_user_profiles
		hives = load_missing_hives()
		profiles = parse_profiles(hives)
		unload_our_hives(hives)
		return profiles
	end

	def unload_our_hives(hives)
		hives.each do |hive|
			next unless hive['OURS']==true
			registry_unloadkey(hive['HKU'])
		end
	end

	def parse_profiles(hives)
		profiles=[]
		hives.each do |hive|
			profile = parse_profile(hive)
			profiles << profile
		end
		return profiles
	end

	def parse_profile(hive)
		profile={}
		#print_status("Parsing User Profile from Registry Hive: #{hive['HKU']}")
		profile['UserName'] = registry_getvaldata("#{hive['HKU']}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer", 'Logon User Name')
		if profile['UserName'] == nil
			profile['UserName'] = registry_getvaldata("#{hive['HKU']}\\Volatile Environment", 'USERNAME')
		end
		profile['SID'] = hive['SID']
		profile['ProfileDir'] = hive['PROF']
		profile['AppData'] = registry_getvaldata("#{hive['HKU']}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", 'AppData')
		profile['LocalAppData'] = registry_getvaldata("#{hive['HKU']}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", 'Local AppData')
		profile['LocalSettings'] = registry_getvaldata("#{hive['HKU']}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", 'Local Settings')
		profile['Desktop'] = registry_getvaldata("#{hive['HKU']}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", 'Desktop')
		profile['MyDocs'] = registry_getvaldata("#{hive['HKU']}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", 'Personal')
		profile['Favorites'] = registry_getvaldata("#{hive['HKU']}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", 'Favorites')
		profile['History'] = registry_getvaldata("#{hive['HKU']}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", 'History')
		profile['Cookies'] = registry_getvaldata("#{hive['HKU']}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", 'Cookies')

		return profile
	end


	def load_missing_hives
		hives=[]
		read_profile_list().each do |hive|
			if hive['LOADED']== false
				registry_loadkey(hive['HKU'], hive['DAT'])
				hive['OURS']=true
				
			else
				hive['OURS']=false
			end
			hives << hive
		end
		return hives
	end

	def read_profile_list
		hives=[]
		registry_enumkeys('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList').each do |profkey|
			next unless profkey.include? "S-1-5-21"
			hive={}
			hive['SID']=profkey
			hive['HKU']= "HKU\\#{profkey}"
			hive['PROF']= registry_getvaldata("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\#{profkey}", 'ProfileImagePath')
			hive['PROF']= session.fs.file.expand_path(hive['PROF'])
			hive['DAT']= "#{hive['PROF']}\\NTUSER.DAT"
			hive['LOADED'] = loaded_hives.include?(profkey)
			hives << hive
		end
		return hives
	end
		
	def loaded_hives
		hives=[]
		registry_enumkeys('HKU').each do |k|
			next unless k.include? "S-1-5-21"
			next if k.include? "_Classes"
			hives<< k
		end
		return hives
	end

end
end
end
end
