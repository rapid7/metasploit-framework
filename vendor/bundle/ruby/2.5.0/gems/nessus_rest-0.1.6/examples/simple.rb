#!/usr/bin/env ruby

require 'nessus_rest'

n=NessusREST::Client.new({:url=>'https://localhost:8834', :username=>'user', :password=> 'password'})
qs=n.scan_quick_template('basic','name-of-scan','localhost')
scanid=qs['scan']['id']
n.scan_wait4finish(scanid)
n.report_download_file(scanid,"csv","myscanreport.csv")



