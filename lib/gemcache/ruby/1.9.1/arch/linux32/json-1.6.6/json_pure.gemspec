# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "json_pure"
  s.version = "1.6.6"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Florian Frank"]
  s.date = "2012-03-26"
  s.description = "This is a JSON implementation in pure Ruby."
  s.email = "flori@ping.de"
  s.extra_rdoc_files = ["README.rdoc"]
  s.files = [".gitignore", ".travis.yml", "CHANGES", "COPYING", "COPYING-json-jruby", "GPL", "Gemfile", "README-json-jruby.markdown", "README.rdoc", "Rakefile", "TODO", "VERSION", "data/example.json", "data/index.html", "data/prototype.js", "diagrams/.keep", "ext/json/ext/fbuffer/fbuffer.h", "ext/json/ext/generator/extconf.rb", "ext/json/ext/generator/generator.c", "ext/json/ext/generator/generator.h", "ext/json/ext/parser/extconf.rb", "ext/json/ext/parser/parser.c", "ext/json/ext/parser/parser.h", "ext/json/ext/parser/parser.rl", "install.rb", "java/src/json/ext/ByteListTranscoder.java", "java/src/json/ext/Generator.java", "java/src/json/ext/GeneratorMethods.java", "java/src/json/ext/GeneratorService.java", "java/src/json/ext/GeneratorState.java", "java/src/json/ext/OptionsReader.java", "java/src/json/ext/Parser.java", "java/src/json/ext/Parser.rl", "java/src/json/ext/ParserService.java", "java/src/json/ext/RuntimeInfo.java", "java/src/json/ext/StringDecoder.java", "java/src/json/ext/StringEncoder.java", "java/src/json/ext/Utils.java", "json-java.gemspec", "json.gemspec", "json_pure.gemspec", "lib/json.rb", "lib/json/add/bigdecimal.rb", "lib/json/add/complex.rb", "lib/json/add/core.rb", "lib/json/add/date.rb", "lib/json/add/date_time.rb", "lib/json/add/exception.rb", "lib/json/add/ostruct.rb", "lib/json/add/range.rb", "lib/json/add/rational.rb", "lib/json/add/regexp.rb", "lib/json/add/struct.rb", "lib/json/add/symbol.rb", "lib/json/add/time.rb", "lib/json/common.rb", "lib/json/ext.rb", "lib/json/ext/.keep", "lib/json/pure.rb", "lib/json/pure/generator.rb", "lib/json/pure/parser.rb", "lib/json/version.rb", "tests/fixtures/fail1.json", "tests/fixtures/fail10.json", "tests/fixtures/fail11.json", "tests/fixtures/fail12.json", "tests/fixtures/fail13.json", "tests/fixtures/fail14.json", "tests/fixtures/fail18.json", "tests/fixtures/fail19.json", "tests/fixtures/fail2.json", "tests/fixtures/fail20.json", "tests/fixtures/fail21.json", "tests/fixtures/fail22.json", "tests/fixtures/fail23.json", "tests/fixtures/fail24.json", "tests/fixtures/fail25.json", "tests/fixtures/fail27.json", "tests/fixtures/fail28.json", "tests/fixtures/fail3.json", "tests/fixtures/fail4.json", "tests/fixtures/fail5.json", "tests/fixtures/fail6.json", "tests/fixtures/fail7.json", "tests/fixtures/fail8.json", "tests/fixtures/fail9.json", "tests/fixtures/pass1.json", "tests/fixtures/pass15.json", "tests/fixtures/pass16.json", "tests/fixtures/pass17.json", "tests/fixtures/pass2.json", "tests/fixtures/pass26.json", "tests/fixtures/pass3.json", "tests/setup_variant.rb", "tests/test_json.rb", "tests/test_json_addition.rb", "tests/test_json_encoding.rb", "tests/test_json_fixtures.rb", "tests/test_json_generate.rb", "tests/test_json_string_matching.rb", "tests/test_json_unicode.rb", "tools/fuzz.rb", "tools/server.rb", "./tests/test_json.rb", "./tests/test_json_addition.rb", "./tests/test_json_encoding.rb", "./tests/test_json_fixtures.rb", "./tests/test_json_generate.rb", "./tests/test_json_string_matching.rb", "./tests/test_json_unicode.rb"]
  s.homepage = "http://flori.github.com/json"
  s.rdoc_options = ["--title", "JSON implemention for ruby", "--main", "README.rdoc"]
  s.require_paths = ["lib"]
  s.rubyforge_project = "json"
  s.rubygems_version = "1.8.21"
  s.summary = "JSON Implementation for Ruby"
  s.test_files = ["./tests/test_json.rb", "./tests/test_json_addition.rb", "./tests/test_json_encoding.rb", "./tests/test_json_fixtures.rb", "./tests/test_json_generate.rb", "./tests/test_json_string_matching.rb", "./tests/test_json_unicode.rb"]

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<permutation>, [">= 0"])
      s.add_development_dependency(%q<sdoc>, [">= 0"])
      s.add_development_dependency(%q<rake>, ["~> 0.9.2"])
    else
      s.add_dependency(%q<permutation>, [">= 0"])
      s.add_dependency(%q<sdoc>, [">= 0"])
      s.add_dependency(%q<rake>, ["~> 0.9.2"])
    end
  else
    s.add_dependency(%q<permutation>, [">= 0"])
    s.add_dependency(%q<sdoc>, [">= 0"])
    s.add_dependency(%q<rake>, ["~> 0.9.2"])
  end
end
