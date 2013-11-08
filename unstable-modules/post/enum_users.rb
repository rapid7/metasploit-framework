##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'

# Multi platform requiere
require 'msf/core/post/common'
require 'msf/core/post/file'

require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post

  include Msf::Post::Common
  include Msf::Post::File
  
  include Msf::Post::Windows::Registry

  def initialize(info={})
    super( update_info( info,
        'Name'		  => 'Windows Gather Enumerate Domain Users',
        'Description'   => %q{ 
            This module will enumerate users included in the 'Domain Users' group for the primary Domain.
        },
        'License'	   => MSF_LICENSE,
        'Author'		=> [ 'Joshua Abraham <jabra[at]rapid7.com>'],
        'Platform'	  => [ 'win'],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
  end

  # Run Method for when run command is issued
  def run
    print_status("Running module against #{sysinfo['Computer']}") if not sysinfo.nil?
    domain = get_domain()
    
    if not domain.empty?
      dom_users = list_domain_group_mem("Domain Users")
      list_group_members(domain, dom_users)
    end
  end
  
  # List Members of a domain group
  def list_domain_group_mem(group)
    account_list = []
    devisor = "-------------------------------------------------------------------------------\r\n"
    raw_list = client.shell_command_token("net groups \"#{group}\" /domain").split(devisor)[1]
    if raw_list =~ /The command completed successfully/
      raw_list.sub!(/The command completed successfully\./,'')
      raw_list.split(" ").each do |m|
        account_list << m
      end
    end
    return account_list
  end
  
  # Gets the Domain Name
  def get_domain()
    domain = ""
    begin
      subkey = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History"
      v_name = "DCName"
      domain_dc = registry_getvaldata(subkey, v_name)
      dom_info =  domain_dc.split('.')
      domain = dom_info[1].upcase
    rescue
      print_error("This host is not part of a domain.")
    end
    return domain
  end
  
  def list_group_members(domain,dom_users)
    tbl = Rex::Ui::Text::Table.new(
      'Header'  => "List of Domain Users for the primary Domain.",
      'Indent'  => 1,
      'Columns' =>
      [
          "Domain",
        "Group",
        "Member",
      ])
    dom_users.each do |user|
      tbl << [domain,"Domain Users",user]
    end
    results = tbl.to_s
    print_line("\n" + results + "\n")
  end
end
