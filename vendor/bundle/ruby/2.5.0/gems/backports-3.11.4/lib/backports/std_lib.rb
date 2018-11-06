# Will intercept future and past 'require' calls of std_lib
# and load additionally the updated libraries.
require 'backports/tools/std_lib'
require 'backports/tools/alias_method_chain'

module Kernel
  def require_with_backports(lib)
    begin
      return false unless require_without_backports(lib)
      paths = Backports::StdLib.extended_lib.fetch(lib, nil)
    rescue LoadError
      return false if Backports::StdLib::LoadedFeatures.new.include?(lib)
      raise unless paths = Backports::StdLib.extended_lib.fetch(lib, nil)
      Backports::StdLib::LoadedFeatures.mark_as_loaded(lib)
    end
    if paths
      paths.each do |path|
        require_without_backports(path)
      end
    end
    true
  end
  Backports.alias_method_chain self, :require, :backports
end
