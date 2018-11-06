if RUBY_VERSION < '1.9'
  require 'backports/tools/path'

  class << File
    def expand_path_with_potential_to_path(file, dir = nil)
      raise ArgumentError, 'home not set' if file == '~' && ENV["HOME"] == ''
      expand_path_without_potential_to_path(
        Backports.convert_path(file),
        dir == nil ? dir : Backports.convert_path(dir)
      )
    end
    Backports.alias_method_chain self, :expand_path, :potential_to_path
  end
end
