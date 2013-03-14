module Spork::GemHelpers
  extend self

  class GemPath
    attr_reader :name, :version, :path, :version_numbers
    include Comparable
    def initialize(p)
      @path = p
      @name, @version = File.basename(p).scan(/^(.+?)-([^-]+)$/).flatten
      @version_numbers = @version.split(/[^0-9]+/).map(&:to_i)
    end

    def <=>(other)
      raise "Not comparable gem paths ('#{name}' is not '#{other.name}')" unless name == other.name
      @version_numbers <=> other.version_numbers
    end
  end

  def latest_load_paths
    case
    when defined?(Bundler)
      $LOAD_PATH.map { |p| File.expand_path(p) }.uniq
    when Gem.respond_to?(:path)
      Dir["{#{Gem.path.join(',')}}" + "/gems/*"].inject({}) do |h,f|
        gem_path = GemPath.new(f)
        if h[gem_path.name]
          h[gem_path.name] = gem_path if gem_path > h[gem_path.name]
        else
          h[gem_path.name] = gem_path
        end
        h
      end.values.map { |gem_path| File.expand_path("lib", gem_path.path) }.sort.uniq
    else
      STDERR.puts "No mechanism available to scan for other gems implementing spork hooks. "
      []
    end
  end
end
