# -*- ruby -*-
require 'rubygems'

gem 'hoe'
require 'hoe'
Hoe.plugin :debugging
Hoe.plugin :git
Hoe.plugin :gemspec
Hoe.plugin :bundler
Hoe.add_include_dirs '.' # for ruby 1.9.2

GENERATED_PARSER    = "lib/nokogiri/css/parser.rb"
GENERATED_TOKENIZER = "lib/nokogiri/css/tokenizer.rb"
CROSS_DIR           =  File.join(File.dirname(__FILE__), 'ports')

def java?
  !! (RUBY_PLATFORM =~ /java/)
end

require 'tasks/nokogiri.org'

HOE = Hoe.spec 'nokogiri' do
  developer 'Aaron Patterson', 'aaronp@rubyforge.org'
  developer 'Mike Dalessio',   'mike.dalessio@gmail.com'
  developer 'Yoko Harada',     'yokolet@gmail.com'

  self.readme_file  = ['README',    ENV['HLANG'], 'rdoc'].compact.join('.')
  self.history_file = ['CHANGELOG', ENV['HLANG'], 'rdoc'].compact.join('.')

  self.extra_rdoc_files = FileList['*.rdoc','ext/nokogiri/*.c']

  self.clean_globs += [
    'nokogiri.gemspec',
    'lib/nokogiri/nokogiri.{bundle,jar,rb,so}',
    'lib/nokogiri/1.{8,9}',
    GENERATED_PARSER,
    GENERATED_TOKENIZER
  ]

  self.extra_dev_deps += [
    ["hoe-bundler",     ">= 1.1"],
    ["hoe-debugging",   ">= 1.0.3"],
    ["hoe-gemspec",     ">= 1.0"],
    ["hoe-git",         ">= 1.4"],
    ["mini_portile",    ">= 0.2.2"],
    ["minitest",        "~> 2.2.2"],
    ["racc",            ">= 1.4.6"],
    ["rake-compiler",   "=  0.8.0"],
    ["rexical",         ">= 1.0.5"],
  ]

  if java?
    self.spec_extras = { :platform => 'java' }
  else
    self.spec_extras = {
      :extensions => ["ext/nokogiri/extconf.rb"],
      :required_ruby_version => '>= 1.8.7'
    }
  end

  self.testlib = :minitest
end

# ----------------------------------------

if java?
  # TODO: clean this section up.
  require "rake/javaextensiontask"
  Rake::JavaExtensionTask.new("nokogiri", HOE.spec) do |ext|
    jruby_home = RbConfig::CONFIG['prefix']
    ext.ext_dir = 'ext/java'
    ext.lib_dir = 'lib/nokogiri'
    jars = ["#{jruby_home}/lib/jruby.jar"] + FileList['lib/*.jar']
    ext.classpath = jars.map { |x| File.expand_path x }.join ':'
  end

  gem_build_path = File.join 'pkg', HOE.spec.full_name

  task gem_build_path => [:compile] do
    cp 'lib/nokogiri/nokogiri.jar', File.join(gem_build_path, 'lib', 'nokogiri')
    HOE.spec.files += ['lib/nokogiri/nokogiri.jar']
  end
else
  mingw_available = true
  begin
    require 'tasks/cross_compile'
  rescue
    mingw_available = false
  end
  require "rake/extensiontask"

  HOE.spec.files.reject! { |f| f =~ %r{\.(java|jar)$} }

  Rake::ExtensionTask.new("nokogiri", HOE.spec) do |ext|
    ext.lib_dir = File.join(*['lib', 'nokogiri', ENV['FAT_DIR']].compact)
    ext.config_options << ENV['EXTOPTS']
    if mingw_available
      ext.cross_compile  = true
      ext.cross_platform = ["x86-mswin32-60", "x86-mingw32"]
      ext.cross_config_options << "--with-xml2-include=#{File.join($recipes[:libxml2].path, 'include', 'libxml2')}"
      ext.cross_config_options << "--with-xml2-lib=#{File.join($recipes[:libxml2].path, 'lib')}"
      ext.cross_config_options << "--with-iconv-dir=#{$recipes[:libiconv].path}"
      ext.cross_config_options << "--with-xslt-dir=#{$recipes[:libxslt].path}"
      ext.cross_config_options << "--with-zlib-dir=#{CROSS_DIR}"
    end
  end
end

# ----------------------------------------

desc "Generate css/parser.rb and css/tokenizer.rex"
task 'generate' => [GENERATED_PARSER, GENERATED_TOKENIZER]
task 'gem:spec' => 'generate' if Rake::Task.task_defined?("gem:spec")

file GENERATED_PARSER => "lib/nokogiri/css/parser.y" do |t|
  racc = RbConfig::CONFIG['target_os'] =~ /mswin32/ ? '' : `which racc`.strip
  racc = "#{::RbConfig::CONFIG['bindir']}/racc" if racc.empty?
  racc = %x{command -v racc}.strip if racc.empty?
  sh "#{racc} -l -o #{t.name} #{t.prerequisites.first}"
end

file GENERATED_TOKENIZER => "lib/nokogiri/css/tokenizer.rex" do |t|
  sh "rex --independent -o #{t.name} #{t.prerequisites.first}"
end

[:compile, :check_manifest].each do |task_name|
  Rake::Task[task_name].prerequisites << GENERATED_PARSER
  Rake::Task[task_name].prerequisites << GENERATED_TOKENIZER
end

# ----------------------------------------

desc "set environment variables to build and/or test with debug options"
task :debug do
  ENV['NOKOGIRI_DEBUG'] = "true"
  ENV['CFLAGS'] ||= ""
  ENV['CFLAGS'] += " -DDEBUG"
end

require 'tasks/test'

Rake::Task[:test].prerequisites << :compile
Rake::Task[:test].prerequisites << :check_extra_deps unless java?
if Hoe.plugins.include?(:debugging)
  ['valgrind', 'valgrind:mem', 'valgrind:mem0'].each do |task_name|
    Rake::Task["test:#{task_name}"].prerequisites << :compile
  end
end

# ----------------------------------------

desc "build a windows gem without all the ceremony."
task "gem:windows" => "gem" do
  cross_rubies = ["1.8.7-p330", "1.9.2-p136"]
  ruby_cc_version = cross_rubies.collect { |_| _.split("-").first }.join(":") # e.g., "1.8.7:1.9.2"
  rake_compiler_config_path = "#{ENV['HOME']}/.rake-compiler/config.yml"

  unless File.exists? rake_compiler_config_path
    raise "rake-compiler has not installed any cross rubies. try running 'env --unset=HOST rake-compiler cross-ruby VERSION=#{cross_rubies.first}'"
  end
  rake_compiler_config = YAML.load_file(rake_compiler_config_path)

  # check that rake-compiler config contains the right patchlevels. see #279 for background,
  # and http://blog.mmediasys.com/2011/01/22/rake-compiler-updated-list-of-supported-ruby-versions-for-cross-compilation/
  # for more up-to-date docs.
  cross_rubies.each do |version|
    majmin, patchlevel = version.split("-")
    rbconfig = "rbconfig-#{majmin}"
    unless rake_compiler_config.key?(rbconfig) && rake_compiler_config[rbconfig] =~ /-#{patchlevel}/
      raise "rake-compiler '#{rbconfig}' not #{patchlevel}. try running 'env --unset=HOST rake-compiler cross-ruby VERSION=#{version}'"
    end
  end

  # verify that --export-all is in the 1.9 rbconfig. see #279,#374,#375.
  rbconfig_19 = rake_compiler_config["rbconfig-1.9.2"]
  raise "rbconfig #{rbconfig_19} needs --export-all in its DLDFLAGS value" if File.read(rbconfig_19).split("\n").grep(/CONFIG\["DLDFLAGS"\].*--export-all/).empty?

  pkg_config_path = [:libxslt, :libxml2].collect { |pkg| File.join($recipes[pkg].path, "lib/pkgconfig") }.join(":")
  sh("env PKG_CONFIG_PATH=#{pkg_config_path} RUBY_CC_VERSION=#{ruby_cc_version} rake cross native gem") || raise("build failed!")
end

# vim: syntax=Ruby
