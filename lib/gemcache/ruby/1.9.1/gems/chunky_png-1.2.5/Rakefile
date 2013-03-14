Dir['tasks/*.rake'].each { |file| load(file) }

GithubGem::RakeTasks.new(:gem)
task :default => [:spec]
