# -*- coding: binary -*-
require 'msf/core/post/common'

module Msf
class Post
module Linux
module Priv
  include ::Msf::Post::Common

  #
  # Returns true if running as root, false if not.
  # @return [Boolean]
  #
  def is_root?
    if command_exists?('id')
      user_id = cmd_exec('id -u')
      clean_user_id = user_id.to_s.gsub(/[^\d]/, '')
      if clean_user_id.empty?
        raise "Could not determine UID: #{user_id.inspect}"
      end
      return (clean_user_id == '0')
    end
    user = whoami
    data = cmd_exec('while read line; do echo $line; done </etc/passwd')
    data.each_line do |line|
      line = line.split(':')
      return true if line[0] == user && line[3].to_i == 0
    end
    false
  end

  #
  # Multiple functions to simulate native commands added
  #

  def download_cmd(remote_path, local_path)
    file_origin = read_file(remote_path)
    `echo "#{file_origin}" > #{local_path}`
  end

  def touch_cmd(new_path_file)
    cmd_exec("> #{new_path_file}")
  end

  def cp_cmd(origin_file, final_file)
    file_origin = read_file(origin_file)
    cmd_exec("echo '#{file_origin}' > #{final_file}")
  end

  def pids()
    dir_proc = "/proc/"
    pids = []

    directories_proc = dir(dir_proc)
    directories_proc.each do |elem|
      elem.gsub( / *\n+/, "")
      if elem[-1] == '1' || elem[-1] == '2' || elem[-1] == '3' || elem[-1] == '4' || elem[-1] == '5' || elem[-1] == '6' || elem[-1] == '7' || elem[-1] == '8' || elem[-1] == '9' || elem[-1] == '0'
        pids.insert(-1, elem)
      end
    end

    return pids.sort_by(&:to_i)
  end

  def binary_of_pid(pid)
    binary = read_file("/proc/#{pid}/cmdline")
    if binary == "" #binary.empty?
      binary = read_file("/proc/#{pid}/comm")
    end
    if binary[-1] == "\n"
      binary = binary.split("\n")[0]
    end
    return binary
  end

  def seq(first, increment, last)
      result = []
      (first..last).step(increment) do |i|
        result.insert(-1, i)
      end
      return result
  end

  def wc_cmd(file)
      [nlines_file(file), nwords_file(file), nchars_file(file), file]
  end

  def nchars_file(file)
    nchars = 0
    lines = read_file(file).split("\n")
    nchars = lines.length()
    lines.each do |line|
      line.gsub(/[ ]/, ' ' => '')
      nchars_line = line.length()
      nchars = nchars + nchars_line
    end
    return nchars
  end

  def nwords_file(file)
    nwords = 0
    lines = read_file(file).split("\n")
    lines.each do |line|
      words = line.split(" ")
      nwords_line = words.length()
      nwords = nwords + nwords_line
    end
    return nwords
  end

  def nlines_file(file)
    lines = read_file(file).split("\n")
    nlines = lines.length()
    return nlines
  end

  def head_cmd(file, nlines)
    lines = read_file(file).split("\n")
    result = lines[0..nlines-1]
    return result
  end

  def tail_cmd(file, nlines)
    lines = read_file(file).split("\n")
    result = lines[-1*(nlines)..-1]
    return result
  end

  def grep_cmd(file, string)
    result = []
    lines = read_file(file).split("\n")

    lines.each do |line|
      if line.include?(string)
        result.insert(-1, line)
      end
    end
    return result
  end



end # Priv
end # Linux
end # Post
end # Msf
