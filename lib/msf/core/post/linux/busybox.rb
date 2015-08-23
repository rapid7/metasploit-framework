# -*- coding: binary -*-

require 'msf/core'

module Msf
class Post
module Linux
module Busybox

  include ::Msf::Post::File

  #
  #Checks if the target file exists
  #@param file_path [String] the target file path
  #@note file? doesnt work because test -f is not implemented in busybox
  #@return [Boolean] True if files exists, otherwise false
  #
  def file_exists(file_path)
    s = read_file(file_path)
    if s and s.length
      return true
    end
    return false
  end

  #
  #Checks if the target directory is writable
  #@param directory_path [String] the target directory path
  #@return [Boolean] True if target directory is writable, otherwise false
  #
  def is_writable_directory(directory_path)
    retval = false
    rand_str = ""; 16.times{rand_str  << (65 + rand(25)).chr}
    file_path = directory_path + "/" + rand_str
    cmd_exec("echo #{rand_str}XXX#{rand_str} > #{file_path}"); Rex::sleep(0.3)
    rcv = read_file(file_path)
    if rcv.include? (rand_str+"XXX"+rand_str)
      retval = true
    end
    cmd_exec("rm -f #{file_path}"); Rex::sleep(0.3)
    return retval
  end

  #
  #Checks if the target file is writable and writes or append to the file the data given as parameter
  #@param file_path [String] the target file path
  #@param data [String] the content to be written to the file
  #@param append [Boolean] if true, append data to the target file. Otherwise, overwrite the target file
  #@note BusyBox shell's commands are limited and Msf > Post > File > write_file function doesnt work here, for this reason it is necessary to implement an specific function
  #@return [Boolean] True if target file is writable and it was written. Otherwise, false.
  #
  def is_writable_and_write(file_path, data, append)
    if append
      writable_directory = get_writable_directory()
      return false if not writable_directory
      cmd_exec("cp -f #{file_path} #{writable_directory}tmp"); Rex::sleep(0.3)
    end
    rand_str = ""; 16.times{rand_str  << (65 + rand(25)).chr}
    cmd_exec("echo #{rand_str} > #{file_path}"); Rex::sleep(0.3)
    if read_file(file_path).include? rand_str
      cmd_exec("echo \"\"> #{file_path}"); Rex::sleep(0.3)
      lines = data.lines.map(&:chomp)
      lines.each do |line|
        cmd_exec("echo #{line.chomp} >> #{file_path}"); Rex::sleep(0.3)
      end
      if append
        cmd_exec("cat #{writable_directory}tmp >> #{file_path}"); Rex::sleep(0.3)
        cmd_exec("rm -f #{writable_directory}tmp"); Rex::sleep(0.3)
      end
      return true
    else
      return false
    end
  end

  #
  #Checks some directories that usually are writable in devices running busybox
  #@return [String] If the function finds a writable directory, it returns the path. Else it returns nil
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
