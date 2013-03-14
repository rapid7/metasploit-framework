require 'rake/rdoctask'

CLEAN.include %w(doc/rdoc)

Rake::RDocTask.new do |rdoc|
  rdoc.rdoc_dir = 'doc/rdoc'
  rdoc.options += ['--quiet', '--title', Thin::NAME,
             	     "--opname", "index.html",
            	     "--line-numbers",
            	     "--main", "README",
            	     "--inline-source"]
  rdoc.template = "site/rdoc.rb"
  rdoc.main = "README"
  rdoc.title = Thin::NAME
  rdoc.rdoc_files.add %w(README) +
                      FileList['lib/**/*.rb'] +
                      FileList['bin/*']
end

namespace :rdoc do
  desc 'Upload rdoc to code.macournoyer.com'
  task :upload => :rdoc do
    upload "doc/rdoc", 'thin/doc', :replace => true
  end
end
