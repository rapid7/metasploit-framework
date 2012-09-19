module Tilt
  VERSION = '1.3.3'

  @preferred_mappings = Hash.new
  @template_mappings = Hash.new { |h, k| h[k] = [] }

  # Hash of template path pattern => template implementation class mappings.
  def self.mappings
    @template_mappings
  end

  def self.normalize(ext)
    ext.to_s.downcase.sub(/^\./, '')
  end

  # Register a template implementation by file extension.
  def self.register(template_class, *extensions)
    if template_class.respond_to?(:to_str)
      # Support register(ext, template_class) too
      extensions, template_class = [template_class], extensions[0]
    end

    extensions.each do |ext|
      ext = normalize(ext)
      mappings[ext].unshift(template_class).uniq!
    end
  end

  # Makes a template class preferred for the given file extensions. If you
  # don't provide any extensions, it will be preferred for all its already
  # registered extensions:
  #
  #   # Prefer RDiscount for its registered file extensions:
  #   Tilt.prefer(Tilt::RDiscountTemplate)
  #
  #   # Prefer RDiscount only for the .md extensions:
  #   Tilt.prefer(Tilt::RDiscountTemplate, '.md')
  def self.prefer(template_class, *extensions)
    if extensions.empty?
      mappings.each do |ext, klasses|
        @preferred_mappings[ext] = template_class if klasses.include? template_class
      end
    else
      extensions.each do |ext|
        ext = normalize(ext)
        register(template_class, ext)
        @preferred_mappings[ext] = template_class
      end
    end
  end

  # Returns true when a template exists on an exact match of the provided file extension
  def self.registered?(ext)
    mappings.key?(ext.downcase) && !mappings[ext.downcase].empty?
  end

  # Create a new template for the given file using the file's extension
  # to determine the the template mapping.
  def self.new(file, line=nil, options={}, &block)
    if template_class = self[file]
      template_class.new(file, line, options, &block)
    else
      fail "No template engine registered for #{File.basename(file)}"
    end
  end

  # Lookup a template class for the given filename or file
  # extension. Return nil when no implementation is found.
  def self.[](file)
    pattern = file.to_s.downcase
    until pattern.empty? || registered?(pattern)
      pattern = File.basename(pattern)
      pattern.sub!(/^[^.]*\.?/, '')
    end

    # Try to find a preferred engine.
    preferred_klass = @preferred_mappings[pattern]
    return preferred_klass if preferred_klass

    # Fall back to the general list of mappings.
    klasses = @template_mappings[pattern]

    # Try to find an engine which is already loaded.
    template = klasses.detect do |klass|
      if klass.respond_to?(:engine_initialized?)
        klass.engine_initialized?
      end
    end

    return template if template

    # Try each of the classes until one succeeds. If all of them fails,
    # we'll raise the error of the first class.
    first_failure = nil

    klasses.each do |klass|
      begin
        klass.new { '' }
      rescue Exception => ex
        first_failure ||= ex
        next
      else
        return klass
      end
    end

    raise first_failure if first_failure
  end

  # Deprecated module.
  module CompileSite
  end

  # Extremely simple template cache implementation. Calling applications
  # create a Tilt::Cache instance and use #fetch with any set of hashable
  # arguments (such as those to Tilt.new):
  #   cache = Tilt::Cache.new
  #   cache.fetch(path, line, options) { Tilt.new(path, line, options) }
  #
  # Subsequent invocations return the already loaded template object.
  class Cache
    def initialize
      @cache = {}
    end

    def fetch(*key)
      @cache[key] ||= yield
    end

    def clear
      @cache = {}
    end
  end


  # Template Implementations ================================================

  require 'tilt/string'
  register StringTemplate, 'str'

  require 'tilt/erb'
  register ERBTemplate,    'erb', 'rhtml'
  register ErubisTemplate, 'erb', 'rhtml', 'erubis'

  require 'tilt/haml'
  register HamlTemplate,   'haml'

  require 'tilt/css'
  register SassTemplate, 'sass'
  register ScssTemplate, 'scss'
  register LessTemplate, 'less'

  require 'tilt/coffee'
  register CoffeeScriptTemplate, 'coffee'

  require 'tilt/nokogiri'
  register NokogiriTemplate, 'nokogiri'

  require 'tilt/builder'
  register BuilderTemplate,  'builder'

  require 'tilt/markaby'
  register MarkabyTemplate,  'mab'

  require 'tilt/liquid'
  register LiquidTemplate, 'liquid'

  require 'tilt/radius'
  register RadiusTemplate, 'radius'

  require 'tilt/markdown'
  register MarukuTemplate,    'markdown', 'mkd', 'md'
  register KramdownTemplate,  'markdown', 'mkd', 'md'
  register BlueClothTemplate, 'markdown', 'mkd', 'md'
  register RDiscountTemplate, 'markdown', 'mkd', 'md'
  register RedcarpetTemplate, 'markdown', 'mkd', 'md'

  require 'tilt/textile'
  register RedClothTemplate, 'textile'

  require 'tilt/rdoc'
  register RDocTemplate, 'rdoc'

  require 'tilt/wiki'
  register CreoleTemplate,    'wiki', 'creole'
  register WikiClothTemplate, 'wiki', 'mediawiki', 'mw'

  require 'tilt/yajl'
  register YajlTemplate, 'yajl'
end
