# -*- coding: binary -*-
require 'msf/core'

module Msf
class Post
module Linux
module Pepa

  include ::Msf::Post::Common
  include ::Msf::Post::File

  def pepa_users()
    result = []
    str_users = cmd_exec("while read line; do echo $line; done </etc/passwd")
    parts = str_users.split("\n")
    parts.each do |line|
        line = line.split(":")
        user = line[0]
        result.insert(-1,user)
    end
    return result
  end

  def pepa_interfaces()
    result = []
    str_interfaces = cmd_exec("for fn in /sys/class/net/*; do echo $fn; done")
    parts = str_interfaces.split("\n")
    parts.each do |line|
        line = line.split("/")[4]
        result.insert(-1,line)
    end
    return result
  end

  def pepa_macs()
    result = []
    str_macs = cmd_exec("for fn in /sys/class/net/*; do echo $fn; done")
    parts = str_macs.split("\n")
    parts.each do |line|
      rut = line + "/address"
      mac_array = pepa_read_file(rut)
      mac_array.each do |mac|
        result.insert(-1,mac)
      end
    end
    return result
  end

  def pepa_shell()
    result = []
    str_shell = cmd_exec("echo $0")
    result.insert(-1,str_shell)
    return result
  end

  def pepa_path()
    result = []
    str_path = cmd_exec("echo $PATH")
    result.insert(-1,str_path)
    return result
  end

  def pepa_shell_pid()
    str_pid = cmd_exec("echo $$")
    return str_pid
  end

  def pepa_pid_uid(pid)
    file_pid = "/proc/" + pid.to_s + "/status"
    result = pepa_read_file(file_pid)
    return result
  end

  def pepa_ips()
    lines = pepa_read_file("/proc/net/fib_trie")
    result = []
    previous_line = ""
    lines.each do |line|
      if line.include?("/32 host LOCAL")
        previous_line = previous_line.split("-- ")[1]
        result.insert(-1, previous_line)
      end
      previous_line = line
    end
    result = pepa_uniq(result)
    return result
  end

  def pepa_isroot?(user)
    result = []
    found = 0
    str_file = cmd_exec("while read line; do echo $line; done </etc/passwd")
    parts = str_file.split("\n")
    parts.each do |line|
      line = line.split(":")
      user_passwd = line[0]
      if user_passwd = user
        found = 1
        result.insert(-1, "True")
      end
    end
    if found == 0
      result.insert(-1, "False")
    end
    return result
  end

  # Parsing information based on: https://github.com/sensu-plugins/sensu-plugins-network-checks/blob/master/bin/check-netstat-tcp.rb
  def pepa_listen_tcp_ports()
    ports = []
    content = pepa_read_file('/proc/net/tcp')
    content.each do |line|
      if m = line.match(/^\s*\d+:\s+(.{8}|.{32}):(.{4})\s+(.{8}|.{32}):(.{4})\s+(.{2})/)
        connection_state = m[5].to_s
        if connection_state == "0A"
          connection_port = m[2].to_i(16)
          if ports.include?(connection_port) == false
            ports.insert(-1, connection_port)
          end
        end
      end
    end
    return ports
  end

  # Parsing information based on: https://github.com/sensu-plugins/sensu-plugins-network-checks/blob/master/bin/check-netstat-tcp.rb
  def pepa_listen_udp_ports()
    ports = []
    content = pepa_read_file('/proc/net/udp')
    content.each do |line|
      if m = line.match(/^\s*\d+:\s+(.{8}|.{32}):(.{4})\s+(.{8}|.{32}):(.{4})\s+(.{2})/)
        connection_state = m[5].to_s
        if connection_state == "07"
                connection_port = m[2].to_i(16)
                if ports.include?(connection_port) == false
                        ports.insert(-1, connection_port)
                end
        end
      end
    end
    return ports
  end

end # Pepa
end # Linux
end # Post
end # Msf
