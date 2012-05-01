require 'pathname'

module Polyglot
  @registrations ||= {} # Guard against reloading
  @loaded ||= {}

  class PolyglotLoadError < LoadError; end

  class NestedLoadError < LoadError
    def initialize le
      @le = le
    end
    def reraise
      raise @le
    end
  end

  def self.register(extension, klass)
    extension = [extension] unless Array === extension
    extension.each{|e|
      @registrations[e] = klass
    }
  end

  def self.find(file, *options, &block)
    is_absolute = Pathname.new(file).absolute?
    (is_absolute ? [""] : $:).each{|lib|
      base = is_absolute ? "" : lib+File::SEPARATOR
      # In Windows, repeated SEPARATOR chars have a special meaning, avoid adding them
      matches = Dir["#{base}#{file}{,.#{@registrations.keys*',.'}}"]
      # Revisit: Should we do more do if more than one candidate found?
      $stderr.puts "Polyglot: found more than one candidate for #{file}: #{matches*", "}" if matches.size > 1
      if path = matches[0]
        return [ path, @registrations[path.gsub(/.*\./,'')]]
      end
    }
    return nil
  end

  def self.load(*a, &b)
    file = a[0].to_str
    return if @loaded[file] # Check for $: changes or file time changes and reload?
    begin
      source_file, loader = Polyglot.find(file, *a[1..-1], &b)
      if (loader)
        begin
          loader.load(source_file)
          @loaded[file] = true
        rescue LoadError => e
          raise Polyglot::NestedLoadError.new(e)
        end
      else
        raise PolyglotLoadError.new("Failed to load #{file} using extensions #{(@registrations.keys+["rb"]).sort*", "}")
      end
    end
  end
end

module Kernel
  alias polyglot_original_require require

  def require(*a, &b)
    polyglot_original_require(*a, &b)
  rescue LoadError => load_error
    begin
      Polyglot.load(*a, &b)
    rescue Polyglot::NestedLoadError => e
      e.reraise
    rescue LoadError
      # Raise the original exception, possibly a MissingSourceFile with a path
      raise load_error
    end
  end
end
