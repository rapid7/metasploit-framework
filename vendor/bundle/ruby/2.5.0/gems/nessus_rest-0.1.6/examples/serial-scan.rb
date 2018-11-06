#!/usr/bin/env ruby

require 'nessus_rest'

subnets_to_scan=[
  {:name=>'lan1', :targets=>'192.168.1.0/24'},
  {:name=>'lan2', :targets=>'10.1.1.0/24'}
]

n=NessusREST::Client.new(:url=>'https://localhost:8834', :username=>'user', :password=> 'password')

subnets_to_scan.each do |subnet|
  scanname='myscan-'+subnet[:name]
  puts "Scanning: "+scanname
  # you have to specify your own scan policy instead of ping-safe
  qs=n.scan_quick_policy('ping-safe',scanname,subnet[:targets])
  scanid=qs['scan']['id']
  puts "Waiting to finish"
  n.scan_wait4finish(scanid)
  n.report_download_file(scanid,'nessus',scanname+'.nessus')
end

