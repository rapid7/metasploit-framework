# With ziprequire you can load ruby modules from a zip file. This means
# ruby's module include path can include zip-files.
#
# The following example creates a zip file with a single entry 
# <code>log/simplelog.rb</code> that contains a single function 
# <code>simpleLog</code>: 
#
#   require 'zip/zipfilesystem'
#   
#   Zip::ZipFile.open("my.zip", true) {
#     |zf| 
#     zf.file.open("log/simplelog.rb", "w") { 
#       |f|
#       f.puts "def simpleLog(v)"
#       f.puts '  Kernel.puts "INFO: #{v}"'
#       f.puts "end"
#     }
#   }
#
# To use the ruby module stored in the zip archive simply require
# <code>zip/ziprequire</code> and include the <code>my.zip</code> zip 
# file in the module search path. The following command shows one 
# way to do this:
#
#   ruby -rzip/ziprequire -Imy.zip  -e " require 'log/simplelog'; simpleLog 'Hello world' "

#$: << 'data/rubycode.zip' << 'data/rubycode2.zip'


require 'zip/zip'

class ZipList #:nodoc:all
  def initialize(zipFileList)
      @zipFileList = zipFileList
  end

  def get_input_stream(entry, &aProc)
    @zipFileList.each {
      |zfName|
      Zip::ZipFile.open(zfName) {
  |zf|
  begin
    return zf.get_input_stream(entry, &aProc) 
  rescue Errno::ENOENT
  end
      }
    }
    raise Errno::ENOENT,
      "No matching entry found in zip files '#{@zipFileList.join(', ')}' "+
      " for '#{entry}'"
  end
end


module Kernel #:nodoc:all
  alias :oldRequire :require

  def require(moduleName)
    zip_require(moduleName) || oldRequire(moduleName)
  end

  def zip_require(moduleName)
    return false if already_loaded?(moduleName)
    get_resource(ensure_rb_extension(moduleName)) { 
      |zis| 
      eval(zis.read); $" << moduleName 
    }
    return true
  rescue Errno::ENOENT => ex
    return false
  end

  def get_resource(resourceName, &aProc)
    zl = ZipList.new($:.grep(/\.zip$/))
    zl.get_input_stream(resourceName, &aProc)
  end

  def already_loaded?(moduleName)
    moduleRE = Regexp.new("^"+moduleName+"(\.rb|\.so|\.dll|\.o)?$")
    $".detect { |e| e =~ moduleRE } != nil
  end

  def ensure_rb_extension(aString)
    aString.sub(/(\.rb)?$/i, ".rb")
  end
end

# Copyright (C) 2002 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
