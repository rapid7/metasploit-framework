# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "journey"
  s.version = "1.0.4.20120614141756"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Aaron Patterson"]
  s.date = "2012-06-14"
  s.description = "Journey is a router.  It routes requests."
  s.email = ["aaron@tenderlovemaking.com"]
  s.extra_rdoc_files = ["Manifest.txt", "CHANGELOG.rdoc", "README.rdoc"]
  s.files = [".autotest", ".gemtest", ".travis.yml", "CHANGELOG.rdoc", "Gemfile", "Manifest.txt", "README.rdoc", "Rakefile", "journey.gemspec", "lib/journey.rb", "lib/journey/backwards.rb", "lib/journey/core-ext/hash.rb", "lib/journey/formatter.rb", "lib/journey/gtg/builder.rb", "lib/journey/gtg/simulator.rb", "lib/journey/gtg/transition_table.rb", "lib/journey/nfa/builder.rb", "lib/journey/nfa/dot.rb", "lib/journey/nfa/simulator.rb", "lib/journey/nfa/transition_table.rb", "lib/journey/nodes/node.rb", "lib/journey/parser.rb", "lib/journey/parser.y", "lib/journey/parser_extras.rb", "lib/journey/path/pattern.rb", "lib/journey/route.rb", "lib/journey/router.rb", "lib/journey/router/strexp.rb", "lib/journey/router/utils.rb", "lib/journey/routes.rb", "lib/journey/scanner.rb", "lib/journey/visitors.rb", "lib/journey/visualizer/fsm.css", "lib/journey/visualizer/fsm.js", "lib/journey/visualizer/index.html.erb", "test/gtg/test_builder.rb", "test/gtg/test_transition_table.rb", "test/helper.rb", "test/nfa/test_simulator.rb", "test/nfa/test_transition_table.rb", "test/nodes/test_symbol.rb", "test/path/test_pattern.rb", "test/route/definition/test_parser.rb", "test/route/definition/test_scanner.rb", "test/router/test_strexp.rb", "test/router/test_utils.rb", "test/test_route.rb", "test/test_router.rb", "test/test_routes.rb"]
  s.homepage = "http://github.com/rails/journey"
  s.rdoc_options = ["--main", "README.rdoc"]
  s.require_paths = ["lib"]
  s.rubyforge_project = "journey"
  s.rubygems_version = "1.8.22"
  s.summary = "Journey is a router"
  s.test_files = ["test/gtg/test_builder.rb", "test/gtg/test_transition_table.rb", "test/nfa/test_simulator.rb", "test/nfa/test_transition_table.rb", "test/nodes/test_symbol.rb", "test/path/test_pattern.rb", "test/route/definition/test_parser.rb", "test/route/definition/test_scanner.rb", "test/router/test_strexp.rb", "test/router/test_utils.rb", "test/test_route.rb", "test/test_router.rb", "test/test_routes.rb"]

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<minitest>, ["~> 2.11"])
      s.add_development_dependency(%q<racc>, [">= 1.4.6"])
      s.add_development_dependency(%q<rdoc>, ["~> 3.11"])
      s.add_development_dependency(%q<json>, [">= 0"])
      s.add_development_dependency(%q<rdoc>, ["~> 3.10"])
      s.add_development_dependency(%q<hoe>, ["~> 2.13"])
    else
      s.add_dependency(%q<minitest>, ["~> 2.11"])
      s.add_dependency(%q<racc>, [">= 1.4.6"])
      s.add_dependency(%q<rdoc>, ["~> 3.11"])
      s.add_dependency(%q<json>, [">= 0"])
      s.add_dependency(%q<rdoc>, ["~> 3.10"])
      s.add_dependency(%q<hoe>, ["~> 2.13"])
    end
  else
    s.add_dependency(%q<minitest>, ["~> 2.11"])
    s.add_dependency(%q<racc>, [">= 1.4.6"])
    s.add_dependency(%q<rdoc>, ["~> 3.11"])
    s.add_dependency(%q<json>, [">= 0"])
    s.add_dependency(%q<rdoc>, ["~> 3.10"])
    s.add_dependency(%q<hoe>, ["~> 2.13"])
  end
end
