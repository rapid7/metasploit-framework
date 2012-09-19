namespace :deploy do
  task :site => %w(site:upload rdoc:upload)
  
  desc 'Deploy on rubyforge'
  task :gem => %w(gem:upload_rubyforge deploy:site)
end
desc 'Deploy on all servers'
task :deploy => "deploy:gem"

def upload(file, to, options={})
  sh %{ssh macournoyer@code.macournoyer.com "rm -rf code.macournoyer.com/#{to}"} if options[:replace]
  sh %{scp -rq #{file} macournoyer@code.macournoyer.com:code.macournoyer.com/#{to}}
end
