# -*- coding: binary -*-

require 'msf/core'

module Msf
class Post
module Linux
module BusyBox

  include ::Msf::Post::Common
  include ::Msf::Post::File

  # Checks if the file exists in the target
  #
  # @param file_path [String] the target file path
  # @return [Boolean] true if files exists, false otherwise
  # @note Msf::Post::File#file? doesnt work because test -f is not available in busybox
  def busy_box_file_exist?(file_path)
    contents = read_file(file_path)
    if contents.nil? || contents.empty?
      return false
    end

    true
  end

  # Checks if the directory is writable in the target
  #
  # @param dir_path [String] the target directory path
  # @return [Boolean] true if target directory is writable, false otherwise
  def busy_box_is_writable_dir?(dir_path)
    res = false
    rand_str = Rex::Text.rand_text_alpha(16)
    file_path = "#{dir_path}/#{rand_str}"

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

  # Checks some directories that usually are writable in devices running busybox
  # @return [String] If the function finds a writable directory, it returns the path. Else it returns nil
  def busy_box_writable_dir
    dirs = %w(/etc/ /mnt/ /var/ /var/tmp/)

    dirs.each do |d|
      return d if busy_box_is_writable_dir?(d)
    end

    nil
  end


  # Writes data to a file
  #
  # @param file_path [String] the file path to write on the target
  # @param data [String] the content to be written
  # @param prepend [Boolean] if true, prepend the data to the target file. Otherwise, overwrite
  #   the target file
  # @return [Boolean] true if target file is writable and it was written. Otherwise, false.
  # @note BusyBox commands are limited and Msf::Post::File#write_file doesn't work here, because
  #   of it is necessary to implement an specific method.
  def busy_box_write_file(file_path, data, prepend = false)
    if prepend
      dir = busy_box_writable_dir
      return false unless dir
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
end # Busybox
end # Linux
end # Post
end # Msf
