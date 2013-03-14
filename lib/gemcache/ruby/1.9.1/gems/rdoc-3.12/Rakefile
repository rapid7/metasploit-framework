$:.unshift File.expand_path 'lib'
require 'rdoc'
require 'hoe'

ENV['BENCHMARK'] = 'yes'

task :docs    => :generate
task :test    => :generate

PARSER_FILES = %w[
  lib/rdoc/rd/block_parser.rb
  lib/rdoc/rd/inline_parser.rb
]

Hoe.plugin :git
Hoe.plugin :minitest
Hoe.plugin :rdoc_tags

$rdoc_rakefile = true

hoe = Hoe.spec 'rdoc' do
  developer 'Eric Hodel', 'drbrain@segment7.net'
  developer 'Dave Thomas', ''
  developer 'Phil Hagelberg', 'technomancy@gmail.com'
  developer 'Tony Strauss', 'tony.strauss@designingpatterns.com'

  self.rsync_args = '-avz'
  rdoc_locations << 'docs.seattlerb.org:/data/www/docs.seattlerb.org/rdoc/'
  rdoc_locations << 'drbrain@rubyforge.org:/var/www/gforge-projects/rdoc/'

  spec_extras[:post_install_message] = <<-MESSAGE
Depending on your version of ruby, you may need to install ruby rdoc/ri data:

<= 1.8.6 : unsupported
 = 1.8.7 : gem install rdoc-data; rdoc-data --install
 = 1.9.1 : gem install rdoc-data; rdoc-data --install
>= 1.9.2 : nothing to do! Yay!
  MESSAGE

  self.readme_file  = 'README.rdoc'
  self.history_file = 'History.rdoc'
  self.testlib = :minitest
  self.extra_rdoc_files += %w[
    DEVELOPERS.rdoc
    History.rdoc
    LICENSE.rdoc
    LEGAL.rdoc
    README.rdoc
    RI.rdoc
    TODO.rdoc
  ]

  self.clean_globs += PARSER_FILES

  require_ruby_version '>= 1.8.7'
  extra_deps     << ['json',     '~> 1.4']
  extra_dev_deps << ['racc',     '~> 1.4']
  extra_dev_deps << ['minitest', '~> 2']
  extra_dev_deps << ['ZenTest',  '~> 4']

  extra_rdoc_files << 'Rakefile'
  spec_extras['required_rubygems_version'] = '>= 1.3'
  spec_extras['homepage'] = 'http://docs.seattlerb.org/rdoc'
end

task :generate => PARSER_FILES

rule '.rb' => '.ry' do |t|
  racc = Gem.bin_path 'racc', 'racc'

  ruby "-rubygems #{racc} -l -o #{t.name} #{t.source}"
end

path = "pkg/#{hoe.spec.full_name}"

package_parser_files = PARSER_FILES.map do |parser_file|
  package_parser_file = "#{path}/#{parser_file}"
  file package_parser_file => parser_file # ensure copy runs before racc
  package_parser_file
end

task "#{path}.gem" => package_parser_files

# These tasks expect to have the following directory structure:
#
#   git/git.rubini.us/code # Rubinius git HEAD checkout
#   svn/ruby/trunk         # ruby subversion HEAD checkout
#   svn/rdoc/trunk         # RDoc subversion HEAD checkout
#
# If you don't have this directory structure, set RUBY_PATH and/or
# RUBINIUS_PATH.

diff_options = "-urpN --exclude '*svn*' --exclude '*swp' --exclude '*rbc'"
rsync_options = "-avP --exclude '*svn*' --exclude '*swp' --exclude '*rbc' --exclude '*.rej' --exclude '*.orig'"

rubinius_dir = ENV['RUBINIUS_PATH'] || '../../../git/git.rubini.us/code'
ruby_dir = ENV['RUBY_PATH'] || '../../svn/ruby/trunk'

desc "Updates Ruby HEAD with the currently checked-out copy of RDoc."
task :update_ruby do
  sh "rsync #{rsync_options} bin/rdoc #{ruby_dir}/bin/rdoc"
  sh "rsync #{rsync_options} bin/ri #{ruby_dir}/bin/ri"
  sh "rsync #{rsync_options} lib/ #{ruby_dir}/lib"
  sh "rsync #{rsync_options} test/ #{ruby_dir}/test/rdoc"
end

desc "Diffs Ruby HEAD with the currently checked-out copy of RDoc."
task :diff_ruby do
  options = "-urpN --exclude '*svn*' --exclude '*swp' --exclude '*rbc'"

  sh "diff #{diff_options} bin/rdoc #{ruby_dir}/bin/rdoc; true"
  sh "diff #{diff_options} bin/ri #{ruby_dir}/bin/ri; true"
  sh "diff #{diff_options} lib/rdoc.rb #{ruby_dir}/lib/rdoc.rb; true"
  sh "diff #{diff_options} lib/rdoc #{ruby_dir}/lib/rdoc; true"
  sh "diff #{diff_options} test #{ruby_dir}/test/rdoc; true"
end

desc "Updates Rubinius HEAD with the currently checked-out copy of RDoc."
task :update_rubinius do
  sh "rsync #{rsync_options} bin/rdoc #{rubinius_dir}/lib/bin/rdoc.rb"
  sh "rsync #{rsync_options} bin/ri #{rubinius_dir}/lib/bin/ri.rb"
  sh "rsync #{rsync_options} lib/ #{rubinius_dir}/lib"
  sh "rsync #{rsync_options} test/ #{rubinius_dir}/test/rdoc"
end

desc "Diffs Rubinius HEAD with the currently checked-out copy of RDoc."
task :diff_rubinius do
  sh "diff #{diff_options} bin/rdoc #{rubinius_dir}/lib/bin/rdoc.rb; true"
  sh "diff #{diff_options} bin/ri #{rubinius_dir}/lib/bin/ri.rb; true"
  sh "diff #{diff_options} lib/rdoc.rb #{rubinius_dir}/lib/rdoc.rb; true"
  sh "diff #{diff_options} lib/rdoc #{rubinius_dir}/lib/rdoc; true"
  sh "diff #{diff_options} test #{rubinius_dir}/test/rdoc; true"
end


