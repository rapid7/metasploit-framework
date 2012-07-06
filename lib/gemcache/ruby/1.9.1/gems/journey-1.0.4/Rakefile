# -*- ruby -*-

require 'rubygems'
require 'hoe'

Hoe.plugins.delete :rubyforge
Hoe.plugin :minitest
Hoe.plugin :gemspec # `gem install hoe-gemspec`
Hoe.plugin :git     # `gem install hoe-git`
Hoe.plugin :bundler # `gem install hoe-bundler`

Hoe.spec 'journey' do
  developer('Aaron Patterson', 'aaron@tenderlovemaking.com')
  self.readme_file      = 'README.rdoc'
  self.history_file     = 'CHANGELOG.rdoc'
  self.extra_rdoc_files = FileList['*.rdoc']
  self.extra_dev_deps += [
    ["racc",            ">= 1.4.6"],
    ["rdoc",            "~> 3.11"],
    ["json"],
  ]
end

rule '.rb' => '.y' do |t|
  sh "racc -l -o #{t.name} #{t.source}"
end

task :compile => "lib/journey/parser.rb"

Rake::Task[:test].prerequisites.unshift "lib/journey/parser.rb"

# vim: syntax=ruby
