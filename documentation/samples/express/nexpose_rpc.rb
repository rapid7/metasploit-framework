#!/usr/bin/env ruby

require '/opt/metasploit-3.5.0/apps/pro/engine/lib/pro/client'

pro = Pro::Client.new() ## this will connect to the rpc service running on localhost:50505 

pro.call('db.add_workspace', "nexpose_custom_scan") ## create a workspace
pro.call('db.set_workspace', "nexpose_custom_scan") ## set that workspace

conf = {
	'workspace'           => "default",
	'username'            => "rpc",
	'DS_WHITELIST_HOSTS'  => "10.0.0.1",
	'DS_BLACKLIST_HOSTS'  => "",
	'DS_NEXPOSE_HOST'     => "localhost",
 	'DS_NEXPOSE_PORT'     => "3780",
 	'DS_NEXPOSE_USER'     => "nxadmin" ,
	'DS_SCAN_TEMPLATE'    => "custom-nmap-scan-template",
	'nexpose_pass'        => "password",
	'nexpose_credentials' => "",
	'DS_NEXPOSE_PURGE_SITE' => "false"
}

puts "starting nexpose task"
ret = pro.start_nexpose(conf)

task_id = ret['task_id']
puts "started nexpose task " + task_id

pro.task_wait(ret['task_id'])
puts "done!"
