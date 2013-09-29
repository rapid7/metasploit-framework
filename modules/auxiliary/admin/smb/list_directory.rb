##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB
  include Msf::Auxiliary::Report

  # Aliases for common classes
  SIMPLE = Rex::Proto::SMB::Client
  XCEPT  = Rex::Proto::SMB::Exceptions
  CONST  = Rex::Proto::SMB::Constants


  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'SMB Directory Listing Utility',
            'Description' => %Q{
              This module lists the directory of a target share and path. The only reason
              to use this module is if your existing SMB client is not able to support the features
              of the Metasploit Framework that you need, like pass-the-hash authentication.
            },
            'Author'      =>
                [
                    'mubix',
                    'hdm'
                ],
            'References'  =>
                [
                ],
            'License'     => MSF_LICENSE
        )
    )

    register_options([
      OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server', 'C$']),
      OptString.new('RPATH', [false, 'The name of the remote directory relative to the share']),
    ], self.class)

  end

  def as_size( s )
    prefix = %W(TB GB MB KB B)
    s = s.to_f
    i = prefix.length - 1
    while s > 512 && i > 0
      s /= 1024
      i -= 1
    end
    ((s > 9 || s.modulo(1) < 0.1 ? '%d' : '%.1f') % s) + ' ' + prefix[i]
  end

  def run
    print_status("Connecting to the server...")
    begin
      connect()
      smb_login()
      print_status("Mounting the remote share \\\\#{datastore['RHOST']}\\#{datastore['SMBSHARE']}'...")
            self.simple.connect("\\\\#{datastore['RHOST']}\\#{datastore['SMBSHARE']}")
      if datastore['RPATH']
        print_status("Listing \\\\#{datastore['RHOST']}\\#{datastore['SMBSHARE']}\\#{datastore['RPATH']}'...")
      end
      listing = self.simple.client.find_first("\\#{datastore['RPATH']}\\*")
      directory = Rex::Ui::Text::Table.new(
            'Header' => "Directory Listing of \\\\#{datastore['RHOST']}\\#{datastore['SMBSHARE']}\\#{datastore['RPATH']}",
            'Indent' => 2,
            'SortIndex' => 2,
            'Columns' => ['SIZE','TYPE','TIME','FILENAME']
      )
      listing.each_pair do |key,val|
        file_lastmodified = ::Time.at(Rex::Proto::SMB::Utils.time_smb_to_unix(val["info"][9],val["info"][10]))
        size = val['info'][10]
        if val['attr'] == 16
          type = 'DIR'
          size = ''
        else
          type = 'FILE'
        end
        directory << [as_size(size.to_s),val["type"],file_lastmodified.strftime("%Y-%m-%d %H:%m:%S%p"),key]
      end
      print_status(directory.to_s)
    rescue Rex::Proto::SMB::Exceptions::Error => e
      # SMB has very good explanations in error messages, don't really need to
      # prefix with anything here.
      print_error("#{e}")
    end
  end
end

