# -*- coding: binary -*-

require 'msf/core'

module Msf
class Post
module Linux
module Vulnerateca

  include ::Msf::Post::Common
  include ::Msf::Post::File

  def vulnerateca_ls(d)
    result = vulnerateca_list_directory(d)
    return result
  end

  def vulnerateca_cat(f)
    result = vulnerateca_read_file(f)
    return result
  end

  def vulnerateca_pwd()
    result = []
    str_pwd = cmd_exec("echo $PWD")
    result.insert(-1,str_pwd)
    return result
  end

  def vulnerateca_uniq(list)
    uniq_list = []
    list.each do |elem|
      if not uniq_list.include?(elem)
        uniq_list.insert(-1, elem)
      end
    end
    return uniq_list
  end

  def vulnerateca_whoami()
    result = []
    shellpid = vulnerateca_shell_pid()
    statuspid = vulnerateca_pid_uid(shellpid)   

    statuspid.each do |line|
        split = line.split(":")
        if split[0] == "Uid"
                regex = /.*\s(.*)\s/
                useridtmp = split[1]
                userid = useridtmp[regex, 1]
                uid = userid.to_s
                passwd = vulnerateca_read_file("/etc/passwd")
                passwd.each do |line|
                        parts = line.split(":")
                        uid_passwd = parts[2].to_s
                        user = parts[0].to_s
                        if uid_passwd == uid
                                result.insert(-1,user)
                                return result
                        end
                end
        end
    end
    return "Error en funcion whoami"
  end

end # Vulnerateca
end # Linux
end # Post
end # Msf
