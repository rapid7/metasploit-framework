#!/usr/bin/env ruby

require 'fileutils'
include FileUtils::Verbose
require 'rbconfig'
include\
  begin
    RbConfig
  rescue NameError
    Config
  end

sitelibdir = CONFIG["sitelibdir"]
cd 'lib' do
  install('json.rb', sitelibdir)
  mkdir_p File.join(sitelibdir, 'json')
  for file in Dir['json/**/*}']
    d = File.join(sitelibdir, file)
    mkdir_p File.dirname(d)
    install(file, d)
  end
end
warn " *** Installed PURE ruby library."
