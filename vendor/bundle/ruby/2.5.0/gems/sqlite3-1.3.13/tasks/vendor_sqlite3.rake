require "rake/clean"
require "rake/extensioncompiler"
require "mini_portile"

CLOBBER.include("ports")

directory "ports"

def define_sqlite_task(platform, host)
  recipe = MiniPortile.new "sqlite3", BINARY_VERSION
  recipe.files << "http://sqlite.org#{URL_PATH}/sqlite-autoconf-#{URL_VERSION}.tar.gz"
  recipe.host = host

  desc "Compile sqlite3 for #{platform} (#{host})"
  task "ports:sqlite3:#{platform}" => ["ports"] do |t|
    checkpoint = "ports/.#{recipe.name}-#{recipe.version}-#{recipe.host}.installed"

    unless File.exist?(checkpoint)
      cflags = "-O2 -DSQLITE_ENABLE_COLUMN_METADATA"
      cflags << " -fPIC" if recipe.host && recipe.host.include?("x86_64")
      recipe.configure_options << "CFLAGS='#{cflags}'"
      recipe.cook
      touch checkpoint
    end
  end

  recipe
end

# native sqlite3 compilation
recipe = define_sqlite_task(RUBY_PLATFORM, RbConfig::CONFIG["host"])

# force compilation of sqlite3 when working natively under MinGW
if RUBY_PLATFORM =~ /mingw/
  RUBY_EXTENSION.config_options << "--with-opt-dir=#{recipe.path}"

  # also prepend DevKit into compilation phase
  Rake::Task["compile"].prerequisites.unshift "devkit", "ports:sqlite3:#{RUBY_PLATFORM}"
  Rake::Task["native"].prerequisites.unshift "devkit", "ports:sqlite3:#{RUBY_PLATFORM}"
end

# trick to test local compilation of sqlite3
if ENV["USE_MINI_PORTILE"] == "true"
  # fake recipe so we can build a directory to it
  recipe = MiniPortile.new "sqlite3", BINARY_VERSION
  recipe.host = RbConfig::CONFIG["host"]

  RUBY_EXTENSION.config_options << "--with-opt-dir=#{recipe.path}"

  # compile sqlite3 first
  Rake::Task["compile"].prerequisites.unshift "ports:sqlite3:#{RUBY_PLATFORM}"
end

# iterate over all cross-compilation platforms and define the proper
# sqlite3 recipe for it.
if RUBY_EXTENSION.cross_compile
  config_path = File.expand_path("~/.rake-compiler/config.yml")
  if File.exist?(config_path)
    # obtains platforms from rake-compiler's config.yml
    config_file = YAML.load_file(config_path)

    Array(RUBY_EXTENSION.cross_platform).each do |platform|
      # obtain platform from rbconfig file
      config_key = config_file.keys.sort.find { |key|
        key.start_with?("rbconfig-#{platform}-")
      }
      rbfile = config_file[config_key]

      # skip if rbconfig cannot be read
      next unless File.exist?(rbfile)

      host = IO.read(rbfile).match(/CONFIG\["CC"\] = "(.*)"/)[1].sub(/\-gcc/, '')
      recipe = define_sqlite_task(platform, host)

      RUBY_EXTENSION.cross_config_options << {
        platform => "--with-opt-dir=#{recipe.path}"
      }

      # pre-compile sqlite3 port when cross-compiling
      task :cross => "ports:sqlite3:#{platform}"
    end
  else
    warn "rake-compiler configuration doesn't exist, but is required for ports"
  end
end

task :cross do
  ["CC", "CXX", "LDFLAGS", "CPPFLAGS", "RUBYOPT"].each do |var|
    ENV.delete(var)
  end
end

desc "Build windows binary gems per rake-compiler-dock."
task "gem:windows" do
  require "rake_compiler_dock"
  RakeCompilerDock.sh "bundle && rake cross native gem MAKE='nice make -j`nproc`'"
end
