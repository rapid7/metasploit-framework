# -*- coding: binary -*-

require 'msf/core'

module Msf
class Post
module Linux
module Vulnerateca

  include ::Msf::Post::Common
  include ::Msf::Post::File

  def vulnerateca_read_file(f)
    result = []
    str_file = cmd_exec("while read line; do echo $line; done <#{f}")
    parts = str_file.split("\n")
    parts.each do |line|
	line = line.strip()
        result.insert(-1,line)
    end
    return result
  end

  def vulnerateca_list_directory(d)
    result = []
    if d == ""
      d = vulnerateca_pwd()[0] + "/"
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

end # Vulnerateca
end # Linux
end # Post
end # Msf
