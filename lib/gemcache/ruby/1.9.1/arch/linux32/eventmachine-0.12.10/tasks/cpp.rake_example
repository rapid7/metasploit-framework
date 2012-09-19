# EventMachine C++ Rakefile Stab Case
# TODO : track header files as a build dependency...
# TODO : cross platform support
# TODO : configure style functionality
namespace :cpp do

  require 'rake/clean'

  # *nix only atm...
  module Cpp
    class <<self
      def cpp; "g++"; end
      def archive; "ar"; end
      def compile file, output, includes=nil, flags=nil
        sh %{#{cpp} #{file} #{includes} #{flags} -c -o #{output}}
      end
      def link file, output, libs=nil, flags=nil
        sh %{#{cpp} #{file} #{libs} #{flags} -o #{output}}
      end
      def static output, files
        sh %{#{archive} cr #{output} #{files}}
      end
    end
  end

  module EmConfig
    Path = ENV['EVENTMACHINE_SOURCE'] || 'ext'
    Sources = FileList["#{Path}/*.cpp"]
    Sources.delete_if { |s| /ruby/ =~ s }
    Compiled = Sources.sub(%r{^#{Path}/(.*)\.cpp}, "#{Path}/\\1.o")

    Flags = "-O2 -pipe -fno-common -DOS_UNIX -DWITHOUT_SSL"
    Includes = ""
    Libs = ''
  end
  CLEAN.include(EmConfig::Compiled)

  rule %r{^#{EmConfig::Path}/.*\.o$} => [proc { |targ| 
    targ.sub(%r{^#{EmConfig::Path}/(.*)\.o$}, "#{EmConfig::Path}/\\1.cpp")
    }] do |t|
    Cpp.compile t.source, t.name, EmConfig::Includes, EmConfig::Flags
  end

  file "#{EmConfig::Path}/libeventmachine.a" => EmConfig::Compiled do |t|
    Cpp.static t.name, EmConfig::Compiled
  end
  CLEAN.include("#{EmConfig::Path}/libeventmachine.a")

  module AppConfig
    Appname = 'echo_em'
    Sources = FileList['*.cpp']
    Compiled = Sources.sub(%r{^(.*)\.cpp}, '\\1.o')

    Flags = ["", EmConfig::Flags].join(' ')
    Includes = ["-I. -I#{EmConfig::Path}", EmConfig::Includes].join(' ')
    Libs = ["-L#{EmConfig::Path} -leventmachine", EmConfig::Libs].join(' ')
  end
  CLEAN.include(AppConfig::Compiled)
  CLEAN.include(AppConfig::Appname)

  rule %r{^.*\.o$} => [proc { |targ| 
    targ.sub(%r{^(.*)\.o$}, '\\1.cpp')
    }] do |t|
    Cpp.compile t.source, t.name, AppConfig::Includes, AppConfig::Flags
  end

  file AppConfig::Appname => ["#{EmConfig::Path}/libeventmachine.a", AppConfig::Compiled] do |t|
    Cpp.link AppConfig::Compiled, t.name, AppConfig::Libs, AppConfig::Flags
  end

  task :build => AppConfig::Appname

  task :run => AppConfig::Appname do
    sh "./#{AppConfig::Appname}"
  end

end