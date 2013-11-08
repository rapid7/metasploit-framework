##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'rex/proto/ntlm/message'


class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::VIMSoap
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'VMWare Enumerate User Accounts',
      'Description'    => %Q{
        This module will log into the Web API of VMWare and try to enumerate
        all the user accounts. If the VMware instance is connected to one or
        more domains, it will try to enumerate domain users as well.
      },
      'Author'         => ['theLightCosine'],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('USERNAME', [ true, "The username to Authenticate with.", 'root' ]),
        OptString.new('PASSWORD', [ true, "The password to Authenticate with.", 'password' ])
      ], self.class)

    register_advanced_options([OptBool.new('SSL', [ false, 'Negotiate SSL for outgoing connections', true]),])
  end


  def run_host(ip)
    if vim_do_login(datastore['USERNAME'], datastore['PASSWORD']) == :success
      #Get local Users and Groups
      user_list = vim_get_user_list(nil)
      tmp_users = Rex::Ui::Text::Table.new(
        'Header'  => "Users for server #{ip}",
        'Indent'  => 1,
        'Columns' => ['Name', 'Description']
      )
      tmp_groups = Rex::Ui::Text::Table.new(
        'Header'  => "Groups for server #{ip}",
        'Indent'  => 1,
        'Columns' => ['Name', 'Description']
      )
      unless user_list.nil?
        case user_list
        when :noresponse
          print_error "Recieved no Response from #{ip}"
        when :expired
          print_error "The login session appears to have expired on #{ip}"
        when :error
          print_error "An error occured while trying to enumerate the users for #{domain} on #{ip}"
        else
          user_list.each do |obj|
            if obj['group'] == 'true'
              tmp_groups << [obj['principal'], obj['fullName']]
            else
              tmp_users <<  [obj['principal'], obj['fullName']]
            end
          end
          print_good tmp_groups.to_s
          store_loot('host.vmware.groups', "text/plain", datastore['RHOST'], tmp_groups.to_csv , "#{datastore['RHOST']}_esx_groups.txt", "VMWare ESX User Groups")
          print_good tmp_users.to_s
          store_loot('host.vmware.users', "text/plain", datastore['RHOST'], tmp_users.to_csv , "#{datastore['RHOST']}_esx_users.txt", "VMWare ESX Users")
        end
      end

      #Enumerate Domains the Server is connected to
      esx_domains = vim_get_domains
      case esx_domains
      when :noresponse
        print_error "Recieved no Response from #{ip}"
      when :expired
        print_error "The login session appears to have expired on #{ip}"
      when :error
        print_error "An error occured while trying to enumerate the domains on #{ip}"
      else
        #Enumerate Domain Users and Groups
        esx_domains.each do |domain|
          tmp_dusers = Rex::Ui::Text::Table.new(
            'Header'  => "Users for domain #{domain}",
            'Indent'  => 1,
            'Columns' => ['Name', 'Description']
          )

          tmp_dgroups = Rex::Ui::Text::Table.new(
            'Header'  => "Groups for domain #{domain}",
            'Indent'  => 1,
            'Columns' => ['Name', 'Description']
          )

          user_list = vim_get_user_list(domain)
          case user_list
          when nil
            next
          when :noresponse
            print_error "Recieved no Response from #{ip}"
          when :expired
            print_error "The login session appears to have expired on #{ip}"
          when :error
            print_error "An error occured while trying to enumerate the users for #{domain} on #{ip}"
          else
            user_list.each do |obj|
              if obj['group'] == 'true'
                tmp_dgroups << [obj['principal'], obj['fullName']]
              else
                tmp_dusers <<  [obj['principal'], obj['fullName']]
              end
            end
            print_good tmp_dgroups.to_s

            f = store_loot('domain.groups', "text/plain", datastore['RHOST'], tmp_dgroups.to_csv , "#{domain}_esx_groups.txt", "VMWare ESX #{domain} Domain User Groups")
            vprint_status("VMWare domain user groups stored in: #{f}")
            print_good tmp_dusers.to_s
            f = store_loot('domain.users', "text/plain", datastore['RHOST'], tmp_dgroups.to_csv , "#{domain}_esx_users.txt", "VMWare ESX #{domain} Domain Users")
            vprint_status("VMWare users stored in: #{f}")
          end
        end
      end
    else
      print_error "Login Failure on #{ip}"
      return
    end
  end

end
