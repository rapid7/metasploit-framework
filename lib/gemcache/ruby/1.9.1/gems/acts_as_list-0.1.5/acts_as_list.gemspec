# -*- encoding: utf-8 -*-
$:.push File.expand_path('../lib', __FILE__)
require 'acts_as_list/version'

Gem::Specification.new do |s|

  # Description Meta...
  s.name        = 'acts_as_list'
  s.version     = ActiveRecord::Acts::List::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ['David Heinemeier Hansson', 'Swanand Pagnis', 'Quinn Chaffee']
  s.email       = ['swanand.pagnis@gmail.com']
  s.homepage    = 'http://github.com/swanandp/acts_as_list'
  s.summary     = %q{A gem allowing a active_record model to act_as_list.}
  s.description = %q{This "acts_as" extension provides the capabilities for sorting and reordering a number of objects in a list. The class that has this specified needs to have a "position" column defined as an integer on the mapped database table.}
  s.rubyforge_project = 'acts_as_list'


  # Load Paths...
  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ['lib']


  # Dependencies (installed via 'bundle install')...
  s.add_development_dependency("bundler", ["~> 1.0.0"])
  s.add_development_dependency("activerecord", [">= 1.15.4.7794"])
  s.add_development_dependency("rdoc")
  s.add_development_dependency("sqlite3")
end
