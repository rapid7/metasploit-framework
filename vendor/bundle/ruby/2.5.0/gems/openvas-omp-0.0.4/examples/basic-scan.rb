#!/usr/bin/env ruby
# Basic example of openvas-omp usage

# in case you're using Ruby 1.8 and using gem, you should uncomment line below
# require 'rubygems'
require 'openvas-omp'

ov=OpenVASOMP::OpenVASOMP.new("user"=>'openvas',"password"=>'openvas')
config=ov.config_get().index("Full and fast")
target=ov.target_create({"name"=>"t", "hosts"=>"127.0.0.1", "comment"=>"t"})
taskid=ov.task_create({"name"=>"t","comment"=>"t", "target"=>target, "config"=>config})
ov.task_start(taskid)
while not ov.task_finished(taskid) do
        stat=ov.task_get_byid(taskid)
        puts "Status: #{stat['status']}, Progress: #{stat['progress']} %"
        sleep 10
end
stat=ov.task_get_byid(taskid)
content=ov.report_get_byid(stat["lastreport"],'HTML')
File.open('report.html', 'w') {|f| f.write(content) }

