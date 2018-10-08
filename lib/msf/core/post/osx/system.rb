# -*- coding: binary -*-

module Msf::Post::OSX::System
  include ::Msf::Post::Common
  include ::Msf::Post::File

  #
  # Return a hash with system Information
  #
  def get_sysinfo
    system_info = {}
    cmd_output = cmd_exec("/usr/bin/sw_vers").split("\n")
    cmd_output.each do |l|
      field,val = l.chomp.split(":")
      system_info[field] = val.strip
    end
    system_info["Kernel"] = cmd_exec("uname -a")
    system_info["Hostname"] = system_info["Kernel"].split(" ")[1]

    return system_info
  end

  #
  # Returns an array of hashes each representing a user on the system
  # Keys are name, gid, uid, dir and shell
  #
  def get_users
    cmd_output = cmd_exec("/usr/bin/dscacheutil -q user")
    users = []
    users_arry = cmd_output.tr("\r", "").split("\n\n")
    users_arry.each do |u|
      entry = Hash.new
      u.each_line do |l|
        field,val = l.chomp.split(": ")
        next if field == "password"
        unless val.nil?
          entry[field] = val.strip
        end
      end
      users << entry
    end
    return users
  end

  #
  # Returns an array of hashes each representing a system accounts on the system
  # Keys are name, gid, uid, dir and shell
  #
  def get_system_accounts
    cmd_output = cmd_exec("/usr/bin/dscacheutil -q user")
    users = []
    users_arry = cmd_output.tr("\r", "").split("\n\n")
    users_arry.each do |u|
      entry = {}
      u.each_line do |l|
        field,val = l.chomp.split(": ")
        next if field == "password"
        unless val.nil?
          entry[field] = val.strip
        end
      end
      next if entry["name"][0] != '_'
      users << entry
    end
    return users
  end

  #
  # Returns an array of hashes each representing non system accounts on the system
  # Keys are name, gid, uid, dir and shell
  #
  def get_nonsystem_accounts
    cmd_output = cmd_exec("/usr/bin/dscacheutil -q user")
    users = []
    users_arry = cmd_output.tr("\r", "").split("\n\n")
    users_arry.each do |u|
      entry = {}
      u.each_line do |l|
        field,val = l.chomp.split(": ")
        next if field == "password"
        unless val.nil?
          entry[field] = val.strip
        end
      end
      next if entry["name"][0] == '_'
      users << entry
    end
    return users
  end

  #
  # Returns an array of hashes each representing user group on the system
  # Keys are name, guid and users
  #
  def get_groups
    cmd_output = cmd_exec("/usr/bin/dscacheutil -q group")
    groups = []
    groups_arry = cmd_output.split("\n\n")
    groups_arry.each do |u|
      entry = Hash.new
      u.each_line do |l|
        field,val = l.chomp.split(": ")
        next if field == "password"
        unless val.nil?
          entry[field] = val.strip
        end
      end
      groups << entry
    end
    return groups
  end
end
