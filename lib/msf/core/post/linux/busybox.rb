# -*- coding: binary -*-

require 'msf/core'

module Msf
class Post
module Linux
module Busybox

  include ::Msf::Post::File

  #
  #file? doesnt work because test -f is not implemented in busybox
  #
  def file_exists(file_path)
    s = read_file(file_path)
    if s and s.length
      return true
    end
    return false
  end

  #
  #This function checks if the target directory is writable
  #
  def is_writable_directory(directory_path)
    retval = false
    rand_str = ""; 16.times{rand_str  << (65 + rand(25)).chr}
    file_path = directory_path + "/" + rand_str
    cmd_exec("echo #{rand_str}XXX#{rand_str} > #{file_path}\n"); Rex::sleep(0.1)
    (1..5).each{session.shell_read(); Rex::sleep(0.1)}
    rcv = read_file(file_path)
    if rcv.include? (rand_str+"XXX"+rand_str)
      retval = true
    end
    cmd_exec("rm -f #{file_path}"); Rex::sleep(0.1)
    return retval
  end

  #
  #This function checks if the target file is writable and writes or append the data given as parameter.
  #BusyBox shell's commands are limited and Msf > Post > File > write_file function doesnt work here, for
  #this reason it is necessary to implement an specific function
  #
  def is_writable_and_write(file_path, data, append)
    if append
      data = read_file(file_path) + "\n" + data
    end
    rand_str = ""; 16.times{rand_str  << (65 + rand(25)).chr}
    cmd_exec("echo #{rand_str} > #{file_path}\n"); Rex::sleep(0.1)
    session.shell_read(); Rex::sleep(0.1)
    if read_file(file_path).include? rand_str
      cmd_exec("echo \"\"> #{file_path}\n"); Rex::sleep(0.1)
      session.shell_read(); Rex::sleep(0.1)
      lines = data.lines.map(&:chomp)
      lines.each do |line|
        cmd_exec("echo #{line.chomp} >> #{file_path}\n"); Rex::sleep(0.1)
        session.shell_read(); Rex::sleep(0.1)
      end
      return true
    else
      return false
    end
  end

  #
  #This function will check some directories that usually are writable in devices running busybox
  #If the function finds a writable directory, it returns the path. Else it returns nil
  #
  def get_writable_directory()
    writable_directory = nil
    writable_directory = "/etc/" if is_writable_directory("/etc")
    writable_directory = "/mnt/" if (!writable_directory && is_writable_directory("/mnt"))
    writable_directory = "/var/" if (!writable_directory && is_writable_directory("/var"))
    writable_directory = "/var/tmp/" if (!writable_directory && is_writable_directory("/var/tmp"))
    return writable_directory
  end

end # Busybox
end # Linux
end # Post
end # Msf
