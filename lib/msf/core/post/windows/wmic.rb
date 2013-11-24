# -*- coding: binary -*-

module Msf
class Post
module Windows

module WMIC

  def wmic_command(server, cmd)
    wcmd = "wmic #{wmic_user_pass_string}/node:#{server} process call create \"#{cmd.gsub('"','\\"')}\""
    vprint_status("[#{server}] #{wcmd}")

    # We dont use cmd_exec as WMIC cannot be Channelized
    ps = session.sys.process.execute(wcmd, "", {'Hidden' => true, 'Channelized' => false})
    select(nil,nil,nil,0.1)
  end

end # Process
end # Windows
end # Post
end # Msf
