begin
  require 'rubygems/package_task'
rescue LoadError
end

require 'rbconfig'
include\
  begin
    RbConfig
  rescue NameError
    Config
  end

require 'rake/clean'
CLOBBER.include 'doc', 'Gemfile.lock'
CLEAN.include FileList['diagrams/*.*'], 'doc', 'coverage', 'tmp',
  FileList["ext/**/{Makefile,mkmf.log}"], 'build', 'dist', FileList['**/*.rbc'],
  FileList["{ext,lib}/**/*.{so,bundle,#{CONFIG['DLEXT']},o,obj,pdb,lib,manifest,exp,def,jar,class,dSYM}"],
  FileList['java/src/**/*.class']

require 'rake/testtask'
class UndocumentedTestTask < Rake::TestTask
  def desc(*) end
end

MAKE   = ENV['MAKE']   || %w[gmake make].find { |c| system(c, '-v') }
BUNDLE = ENV['BUNDLE'] || %w[bundle].find { |c| system(c, '-v') }
PKG_NAME          = 'json'
PKG_TITLE         = 'JSON Implementation for Ruby'
PKG_VERSION       = File.read('VERSION').chomp
PKG_FILES         = FileList[`git ls-files`.split(/\n/)]

EXT_ROOT_DIR      = 'ext/json/ext'
EXT_PARSER_DIR    = "#{EXT_ROOT_DIR}/parser"
EXT_PARSER_DL     = "#{EXT_PARSER_DIR}/parser.#{CONFIG['DLEXT']}"
RAGEL_PATH        = "#{EXT_PARSER_DIR}/parser.rl"
EXT_PARSER_SRC    = "#{EXT_PARSER_DIR}/parser.c"
EXT_GENERATOR_DIR = "#{EXT_ROOT_DIR}/generator"
EXT_GENERATOR_DL  = "#{EXT_GENERATOR_DIR}/generator.#{CONFIG['DLEXT']}"
EXT_GENERATOR_SRC = "#{EXT_GENERATOR_DIR}/generator.c"

JAVA_DIR            = "java/src/json/ext"
JAVA_RAGEL_PATH     = "#{JAVA_DIR}/Parser.rl"
JAVA_PARSER_SRC     = "#{JAVA_DIR}/Parser.java"
JAVA_SOURCES        = FileList["#{JAVA_DIR}/*.java"]
JAVA_CLASSES        = []
JRUBY_PARSER_JAR    = File.expand_path("lib/json/ext/parser.jar")
JRUBY_GENERATOR_JAR = File.expand_path("lib/json/ext/generator.jar")

RAGEL_CODEGEN     = %w[rlcodegen rlgen-cd ragel].find { |c| system(c, '-v') }
RAGEL_DOTGEN      = %w[rlgen-dot rlgen-cd ragel].find { |c| system(c, '-v') }

desc "Installing library (pure)"
task :install_pure => :version do
  ruby 'install.rb'
end

task :install_ext_really do
  sitearchdir = CONFIG["sitearchdir"]
  cd 'ext' do
    for file in Dir["json/ext/*.#{CONFIG['DLEXT']}"]
      d = File.join(sitearchdir, file)
      mkdir_p File.dirname(d)
      install(file, d)
    end
    warn " *** Installed EXT ruby library."
  end
end

desc "Installing library (extension)"
task :install_ext => [ :compile, :install_pure, :install_ext_really ]

desc "Installing library (extension)"
task :install => :install_ext

if defined?(Gem) and defined?(Gem::PackageTask)
  spec_pure = Gem::Specification.new do |s|
    s.name = 'json_pure'
    s.version = PKG_VERSION
    s.summary = PKG_TITLE
    s.description = "This is a JSON implementation in pure Ruby."

    s.files = PKG_FILES

    s.require_path = 'lib'
    s.add_development_dependency 'permutation'
    s.add_development_dependency 'sdoc'
    s.add_development_dependency 'rake', '~>0.9.2'

    s.extra_rdoc_files << 'README.rdoc'
    s.rdoc_options <<
      '--title' <<  'JSON implemention for ruby' << '--main' << 'README.rdoc'
    s.test_files.concat Dir['./tests/test_*.rb']

    s.author = "Florian Frank"
    s.email = "flori@ping.de"
    s.homepage = "http://flori.github.com/#{PKG_NAME}"
    s.rubyforge_project = "json"
  end

  desc 'Creates a json_pure.gemspec file'
  task :gemspec_pure => :version do
    File.open('json_pure.gemspec', 'w') do |gemspec|
      gemspec.write spec_pure.to_ruby
    end
  end

  Gem::PackageTask.new(spec_pure) do |pkg|
      pkg.need_tar = true
      pkg.package_files = PKG_FILES
  end

  spec_ext = Gem::Specification.new do |s|
    s.name = 'json'
    s.version = PKG_VERSION
    s.summary = PKG_TITLE
    s.description = "This is a JSON implementation as a Ruby extension in C."

    s.files = PKG_FILES

    s.extensions = FileList['ext/**/extconf.rb']

    s.require_path = EXT_ROOT_DIR
    s.require_paths << 'ext'
    s.require_paths << 'lib'
    s.add_development_dependency 'permutation'
    s.add_development_dependency 'sdoc'

    s.extra_rdoc_files << 'README.rdoc'
    s.rdoc_options <<
      '--title' <<  'JSON implemention for Ruby' << '--main' << 'README.rdoc'
    s.test_files.concat Dir['./tests/test_*.rb']

    s.author = "Florian Frank"
    s.email = "flori@ping.de"
    s.homepage = "http://flori.github.com/#{PKG_NAME}"
    s.rubyforge_project = "json"
  end

  desc 'Creates a json.gemspec file'
  task :gemspec_ext => :version do
    File.open('json.gemspec', 'w') do |gemspec|
      gemspec.write spec_ext.to_ruby
    end
  end

  Gem::PackageTask.new(spec_ext) do |pkg|
    pkg.need_tar      = true
    pkg.package_files = PKG_FILES
  end


  desc 'Create all gemspec files'
  task :gemspec => [ :gemspec_pure, :gemspec_ext ]
end

desc m = "Writing version information for #{PKG_VERSION}"
task :version do
  puts m
  File.open(File.join('lib', 'json', 'version.rb'), 'w') do |v|
    v.puts <<EOT
module JSON
  # JSON version
  VERSION         = '#{PKG_VERSION}'
  VERSION_ARRAY   = VERSION.split(/\\./).map { |x| x.to_i } # :nodoc:
  VERSION_MAJOR   = VERSION_ARRAY[0] # :nodoc:
  VERSION_MINOR   = VERSION_ARRAY[1] # :nodoc:
  VERSION_BUILD   = VERSION_ARRAY[2] # :nodoc:
end
EOT
  end
end

desc "Testing library (pure ruby)"
task :test_pure => [ :clean, :do_test_pure ]

UndocumentedTestTask.new do |t|
  t.name = 'do_test_pure'
  t.libs << 'lib'
  t.test_files = FileList['tests/test_*.rb']
  t.verbose = true
  t.options = '-v'
end

desc "Testing library (pure ruby and extension)"
task :test do
  sh "env JSON=pure #{BUNDLE} exec rake test_pure" or exit 1
  sh "env JSON=ext #{BUNDLE} exec rake test_ext"  or exit 1
end

namespace :gems do
  desc 'Install all development gems'
  task :install do
    sh "#{BUNDLE}"
  end
end

if defined?(RUBY_ENGINE) and RUBY_ENGINE == 'jruby'
  if ENV.key?('JAVA_HOME')
    warn " *** JAVA_HOME was set to #{ENV['JAVA_HOME'].inspect}"
  else File.directory?(local_java = '/usr/local/java/jdk')
    ENV['JAVA_HOME'] = local_java
    warn " *** JAVA_HOME is set to #{ENV['JAVA_HOME'].inspect}"
    ENV['PATH'] = ENV['PATH'].split(/:/).unshift(java_path = "#{ENV['JAVA_HOME']}/bin") * ':'
    warn " *** java binaries are assumed to be in #{java_path.inspect}"
  end

  file JAVA_PARSER_SRC => JAVA_RAGEL_PATH do
    cd JAVA_DIR do
      if RAGEL_CODEGEN == 'ragel'
        sh "ragel Parser.rl -J -o Parser.java"
      else
        sh "ragel -x Parser.rl | #{RAGEL_CODEGEN} -J"
      end
    end
  end

  desc "Generate parser for java with ragel"
  task :ragel => JAVA_PARSER_SRC

  desc "Delete the ragel generated Java source"
  task :ragel_clean do
    rm_rf JAVA_PARSER_SRC
  end

  JRUBY_JAR = File.join(CONFIG["libdir"], "jruby.jar")
  if File.exist?(JRUBY_JAR)
    JAVA_SOURCES.each do |src|
      classpath = (Dir['java/lib/*.jar'] << 'java/src' << JRUBY_JAR) * ':'
      obj = src.sub(/\.java\Z/, '.class')
      file obj => src do
        sh 'javac', '-classpath', classpath, '-source', '1.5', '-target', '1.5', src
      end
      JAVA_CLASSES << obj
    end
  else
    warn "WARNING: Cannot find jruby in path => Cannot build jruby extension!"
  end

  desc "Compiling jruby extension"
  task :compile => JAVA_CLASSES

  desc "Package the jruby gem"
  task :jruby_gem => :create_jar do
    sh 'gem build json-java.gemspec'
    mkdir_p 'pkg'
    mv "json-#{PKG_VERSION}-java.gem", 'pkg'
  end

  desc "Testing library (jruby)"
  task :test_ext => [ :create_jar, :do_test_ext ]

  UndocumentedTestTask.new do |t|
    t.name = 'do_test_ext'
    t.libs << 'lib'
    t.test_files = FileList['tests/test_*.rb']
    t.verbose = true
    t.options = '-v'
  end

  file JRUBY_PARSER_JAR => :compile do
    cd 'java/src' do
      parser_classes = FileList[
        "json/ext/ByteListTranscoder*.class",
        "json/ext/OptionsReader*.class",
        "json/ext/Parser*.class",
        "json/ext/RuntimeInfo*.class",
        "json/ext/StringDecoder*.class",
        "json/ext/Utils*.class"
      ]
      sh 'jar', 'cf', File.basename(JRUBY_PARSER_JAR), *parser_classes
      mv File.basename(JRUBY_PARSER_JAR), File.dirname(JRUBY_PARSER_JAR)
    end
  end

  desc "Create parser jar"
  task :create_parser_jar => JRUBY_PARSER_JAR

  file JRUBY_GENERATOR_JAR => :compile do
    cd 'java/src' do
      generator_classes = FileList[
        "json/ext/ByteListTranscoder*.class",
        "json/ext/OptionsReader*.class",
        "json/ext/Generator*.class",
        "json/ext/RuntimeInfo*.class",
        "json/ext/StringEncoder*.class",
        "json/ext/Utils*.class"
      ]
      sh 'jar', 'cf', File.basename(JRUBY_GENERATOR_JAR), *generator_classes
      mv File.basename(JRUBY_GENERATOR_JAR), File.dirname(JRUBY_GENERATOR_JAR)
    end
  end

  desc "Create generator jar"
  task :create_generator_jar => JRUBY_GENERATOR_JAR

  desc "Create parser and generator jars"
  task :create_jar => [ :create_parser_jar, :create_generator_jar ]

  desc "Build all gems and archives for a new release of the jruby extension."
  task :build => [ :clean, :version, :jruby_gem ]

  task :release => :build
else
  desc "Compiling extension"
  task :compile => [ EXT_PARSER_DL, EXT_GENERATOR_DL ]

  file EXT_PARSER_DL => EXT_PARSER_SRC do
    cd EXT_PARSER_DIR do
      ruby 'extconf.rb'
      sh MAKE
    end
    cp "#{EXT_PARSER_DIR}/parser.#{CONFIG['DLEXT']}", EXT_ROOT_DIR
  end

  file EXT_GENERATOR_DL => EXT_GENERATOR_SRC do
    cd EXT_GENERATOR_DIR do
      ruby 'extconf.rb'
      sh MAKE
    end
    cp "#{EXT_GENERATOR_DIR}/generator.#{CONFIG['DLEXT']}", EXT_ROOT_DIR
  end

  desc "Testing library (extension)"
  task :test_ext => [ :compile, :do_test_ext ]

  UndocumentedTestTask.new do |t|
    t.name = 'do_test_ext'
    t.libs << 'ext' << 'lib'
    t.test_files = FileList['tests/test_*.rb']
    t.verbose = true
    t.options = '-v'
  end

  desc "Create RDOC documentation"
  task :doc => [ :version, EXT_PARSER_SRC ] do
    sh "sdoc -o doc -t '#{PKG_TITLE}' -m README.rdoc README.rdoc lib/json.rb #{FileList['lib/json/**/*.rb']} #{EXT_PARSER_SRC} #{EXT_GENERATOR_SRC}"
  end

  desc "Generate parser with ragel"
  task :ragel => EXT_PARSER_SRC

  desc "Delete the ragel generated C source"
  task :ragel_clean do
    rm_rf EXT_PARSER_SRC
  end

  file EXT_PARSER_SRC => RAGEL_PATH do
    cd EXT_PARSER_DIR do
      if RAGEL_CODEGEN == 'ragel'
        sh "ragel parser.rl -G2 -o parser.c"
      else
        sh "ragel -x parser.rl | #{RAGEL_CODEGEN} -G2"
      end
      src = File.read("parser.c").gsub(/[ \t]+$/, '')
      File.open("parser.c", "w") {|f| f.print src}
    end
  end

  desc "Generate diagrams of ragel parser (ps)"
  task :ragel_dot_ps do
    root = 'diagrams'
    specs = []
    File.new(RAGEL_PATH).grep(/^\s*machine\s*(\S+);\s*$/) { specs << $1 }
    for s in specs
      if RAGEL_DOTGEN == 'ragel'
        sh "ragel #{RAGEL_PATH} -S#{s} -p -V | dot -Tps -o#{root}/#{s}.ps"
      else
        sh "ragel -x #{RAGEL_PATH} -S#{s} | #{RAGEL_DOTGEN} -p|dot -Tps -o#{root}/#{s}.ps"
      end
    end
  end

  desc "Generate diagrams of ragel parser (png)"
  task :ragel_dot_png do
    root = 'diagrams'
    specs = []
    File.new(RAGEL_PATH).grep(/^\s*machine\s*(\S+);\s*$/) { specs << $1 }
    for s in specs
      if RAGEL_DOTGEN == 'ragel'
        sh "ragel #{RAGEL_PATH} -S#{s} -p -V | dot -Tpng -o#{root}/#{s}.png"
      else
        sh "ragel -x #{RAGEL_PATH} -S#{s} | #{RAGEL_DOTGEN} -p|dot -Tpng -o#{root}/#{s}.png"
      end
    end
  end

  desc "Generate diagrams of ragel parser"
  task :ragel_dot => [ :ragel_dot_png, :ragel_dot_ps ]

  desc "Build all gems and archives for a new release of json and json_pure."
  task :build => [ :clean, :gemspec, :package ]

  task :release => :build
end

desc "Compile in the the source directory"
task :default => [ :clean, :gemspec, :test ]
