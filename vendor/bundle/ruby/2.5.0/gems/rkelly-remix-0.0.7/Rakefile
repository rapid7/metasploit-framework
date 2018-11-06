require 'rubygems'
require 'hoe'

Hoe.plugin :gemspec # `gem install hoe-gemspec`
Hoe.plugin :git     # `gem install hoe-git`

GENERATED_PARSER = "lib/rkelly/generated_parser.rb"

HOE = Hoe.spec('rkelly-remix') do |p|
  developer('Aaron Patterson', 'aaron.patterson@gmail.com')
  developer('Rene Saarsoo', 'rene.saarsoo@sencha.com')
  self.readme_file   = 'README.rdoc'
  self.history_file  = 'CHANGELOG.rdoc'
  self.extra_rdoc_files  = FileList['*.rdoc']
  self.clean_globs   = [GENERATED_PARSER]
end

file GENERATED_PARSER => "lib/parser.y" do |t|
  if ENV['DEBUG']
    sh "racc -g -v -o #{t.name} #{t.prerequisites.first}"
  else
    sh "racc -o #{t.name} #{t.prerequisites.first}"
  end
end

task :parser => GENERATED_PARSER

# make sure the parser's up-to-date when we test
Rake::Task[:test].prerequisites << :parser
Rake::Task[:check_manifest].prerequisites << :parser

namespace :gem do
  task :spec do
    File.open("#{HOE.name}.gemspec", 'w') do |f|
      HOE.spec.version = "#{HOE.version}.#{Time.now.strftime("%Y%m%d%H%M%S")}"
      f.write(HOE.spec.to_ruby)
    end
  end
end
