#!/usr/bin/env ruby

require 'nessus_rest'

n=NessusREST::Client.new({:url=>'https://localhost:8834', :username=>'user', :password=> 'password'})

formats=["nessus","csv","html"]
folders_id=Hash.new

sl=n.list_scans

sl["folders"].each do |f|
  folders_id[f['id']]=f['name']
end

sl["scans"].each do |s|
  puts "backing up: "+s["name"]+":"+s["uuid"].to_s
  formats.each do |format|
    # fn = folder__name__scanid.format
    outputfn=folders_id[s['folder_id']]+'__'+s['name']+'__'+s['id'].to_s+'.'+format
    puts "-> Format: #{format} Filename: #{outputfn}"
    n.report_download_file(s['id'],format,outputfn)
  end # formats
end # scans

