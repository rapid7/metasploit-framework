# -*- coding: binary -*-
require 'msf/core'

module Msf
class Post
module Linux
module Pepa

  include ::Msf::Post::Common
  include ::Msf::Post::File

  def pepa_read_file(f)
    result = []
    str_file = cmd_exec("while read line; do echo $line; done <#{f}")
    parts = str_file.split("\n")
    parts.each do |line|
    line = line.strip()
        result.insert(-1,line)
    end
    return result
  end

  def pepa_list_directory(d)
    result = []
    if d == ""
      d = pepa_pwd()[0] + "/"
    elsif d[-1] == '/'
      d = d
    else
      d = d + "/"
    end
    str_ls = cmd_exec("for fn in #{d}*; do echo $fn; done")
    parts = str_ls.split("\n")
    parts.each do |line|
        line = line.strip()
        result.insert(-1,line)
    end
    return result
  end

end # Pepa
end # Linux
end # Post
end # Msf
