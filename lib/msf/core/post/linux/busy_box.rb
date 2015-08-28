# -*- coding: binary -*-

require 'msf/core'

module Msf
class Post
module Linux
module BusyBox

  include ::Msf::Post::Common
  include ::Msf::Post::File

  # Checks if the target file exists
  # @param file_path [String] the target file path
  # @note file? doesnt work because test -f is not implemented in busybox
  # @return [Boolean] True if files exists, otherwise false
  def busy_box_file_exist?(file_path)
    contents = read_file(file_path)
    if contents and contents.length > 0
      return true
    end

    false
  end

  # Checks if the target directory is writable
  # @param directory_path [String] the target directory path
  # @return [Boolean] True if target directory is writable, otherwise false
  def is_writable_directory?(directory_path)
    res = false
    rand_str = Rex::Text.rand_text_alpha(16)
    file_path = "#{directory_path}"/"#{rand_str}"

    cmd_exec("echo #{rand_str}XXX#{rand_str} > #{file_path}")
    Rex::sleep(0.3)
    rcv = read_file(file_path)

    if rcv.include?("#{rand_str}XXX#{rand_str}")
      res = true
    end

    cmd_exec("rm -f #{file_path}")
    Rex::sleep(0.3)

    res
  end

  # Checks if the target file is writable and writes or append to the file the data given as parameter
  # @param file_path [String] the target file path
  # @param data [String] the content to be written to the file
  # @param append [Boolean] if true, append data to the target file. Otherwise, overwrite the target file
  # @note BusyBox shell's commands are limited and Msf > Post > File > write_file function doesnt work here, for this reason it is necessary to implement an specific function
  # @return [Boolean] True if target file is writable and it was written. Otherwise, false.
  def busybox_write_file(file_path, data, prepend = false)
    if prepend
      cmd_exec("cp -f #{file_path} #{dir}tmp")
      Rex::sleep(0.3)
    end

    rand_str = Rex::Text.rand_text_alpha(16)
    cmd_exec("echo #{rand_str} > #{file_path}")
    Rex::sleep(0.3)

    unless read_file(file_path).include?(rand_str)
      return false
    end

    cmd_exec("echo \"\"> #{file_path}")
    Rex::sleep(0.3)

    lines = data.lines.map(&:chomp)
    lines.each do |line|
      cmd_exec("echo #{line.chomp} >> #{file_path}")
      Rex::sleep(0.3)
    end

    if prepend
      cmd_exec("cat #{dir}tmp >> #{file_path}")
      Rex::sleep(0.3)

      cmd_exec("rm -f #{dir}tmp")
      Rex::sleep(0.3)
    end

    true
  end

  # Checks some directories that usually are writable in devices running busybox
  # @return [String] If the function finds a writable directory, it returns the path. Else it returns nil
  def get_writable_directory
    dirs = ['/etc/', '/mnt/', '/var/', '/var/tmp/']

    dirs.each do |d|
      return d if is_writable_directory?(d)
    end

    nil
  end

end # Busybox
end # Linux
end # Post
end # Msf
