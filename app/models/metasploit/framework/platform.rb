class Metasploit::Framework::Platform < Metasploit::Model::Base
  include Metasploit::Model::Platform

  #
  # Attributes
  #

  # @!attribute [rw] fully_qualified_name
  #   The fully qualified name of this platform, as would be used in the platform list in a metasploit-framework
  #   module.
  #
  #   @return [String]
  attr_accessor :fully_qualified_name

  # @!attribute [rw] parent
  #   The parent platform of this platform.  For example, Windows is parent of Windows 98, which is the parent of
  #   Windows 98 FE.
  #
  #   @return [nil] if this is a top-level platform, such as Windows or Linux.
  #   @return [Metasploit::Framework::Platform]
  attr_accessor :parent

  # @!attribute [rw] relative_name
  #   The name of this platform relative to the {#fully_qualified_name} of {#parent}.
  #
  #   @return [String]
  attr_accessor :relative_name

  #
  # Methods
  #

  def self.all
    # cache so that Metasploit::Framework::Platform can be compared by identity
    unless instance_variable_defined? :@all
      @all = []

      Metasploit::Model::Platform.each_seed_attributes do |attributes|
        child = new(attributes)
        # validate to populate {#fully_qualified_name}
        child.valid!

        @all << child

        # yieldreturn
        child
      end

      # memoize prior to freezing
      @all.map(&:child_set)
      @all.map(&:depth)
      @all.map(&:self_and_descendant_set)

      # freeze objects to prevent specs from modifying them and interfering with other specs.
      @all.map(&:freeze)

      @all.freeze
    end

    @all
  end

  def child_set
    @child_set ||= Set.new
  end

  # The highest platform in the hierarchy that matches the given `string`.  Match is performed by allowing any number of
  # characters between the given characters in `string` and is case-insensitive.
  #
  # @param string [String] a partial `Mdm::Platform#fully_qualified_name`.
  # @param options [Hash{Symbol => Msf::Module}]
  # @option options [Array<String>] :module_class_full_names The `Mdm::Module::Class#full_name`s for the module classes
  #   that declared this platform.
  # @return [Metasploit::Framework::Platform] if there is a match.
  # @raise [ArgumentError] if there is no single match.
  def self.closest(string, options={})
    options.assert_valid_keys(:module_class_full_names)

    if string.empty?
      raise ArgumentError,
            "Empty string is used to indicate all platforms: " \
            "it should be converted directly to Metasploit::Framework::Platform.all " \
            "without calling #{self.class}##{__method__}"
    end

    # check for match ignoring case first
    platform = all.find { |platform|
      platform.fully_qualified_name.casecmp(string) == 0
    }

    unless platform
      pattern = string.each_char.to_a.join(".*")
      anchored_pattern = "\\A#{pattern}"

      regexp = Regexp.new(anchored_pattern, Regexp::IGNORECASE)

      matches = all.select { |platform|
        regexp.match(platform.fully_qualified_name)
      }

      if matches.empty?
        raise ArgumentError, "No Metasploit::Model::Platform#fully_qualified_name matches #{string} expanded to #{regexp}"
      end

      platforms_by_depth = matches.group_by(&:depth)
      minimum_depth = platforms_by_depth.keys.min
      highest_matching_platforms = platforms_by_depth[minimum_depth]

      if highest_matching_platforms.length > 1
        fully_qualified_name_sentence = highest_matching_platforms.map(&:fully_qualified_name).sort.map(&:inspect).to_sentence

        raise ArgumentError,
              "Multiple Metasploit::Model::Platform#fully_qualified_names (#{fully_qualified_name_sentence}) are the " \
              "closest to #{string.inspect}.  Use one of the fully qualified names exactly."
      end

      platform = highest_matching_platforms.first
    end

    if string != platform.fully_qualified_name
      location = ''
      module_class_full_names = options[:module_class_full_names] || []

      unless module_class_full_names.empty?
        module_classes = Mdm::Module::Class.where(full_name: module_class_full_names).includes(:ancestors)

        locations = module_classes.collect { |module_class|
          ancestors = module_class.ancestors
          ancestor_pluralization = 'ancestor'.pluralize(ancestors.size)
          ancestor_sentence = ancestors.map(&:real_path).sort.to_sentence

          "module class (#{module_class.full_name}) defined by its #{ancestor_pluralization} (#{ancestor_sentence})"
        }

        location = " in #{locations.to_sentence}"
      end

      # suppress callstack as its not useful for identifying the ancestor real paths to fix, but location is.
      callstack = []
      ActiveSupport::Deprecation.warn(
          "#{string.inspect} is deprecated as a platform name.  Use #{platform.fully_qualified_name.inspect}#{location} instead.",
          callstack
      )
    end

    platform
  end

  def depth
    unless instance_variable_defined? :@depth
      if parent
        @depth = parent.depth + 1
      else
        @depth = 0
      end
    end

    @depth
  end

  # Sets attributes and adds `self` to {#parent} {#child_set}.
  #
  # @param attributes [Hash{Symbol => Object}]
  # @option attributes [Metasploit::Framework::Platform, nil] :parent parent of this platform or nil if this is a root
  #   platform.
  # @option attributes [String] :relative_name name of this platform relative to `:parent`.
  def initialize(attributes={})
    super

    parent = attributes[:parent]

    if parent
      parent.child_set.add self
    end
  end

  # All platforms under this platform and this platform, in a `Set`.
  #
  # @return [Set<Metasploit::Framework::Platform]
  def self_and_descendant_set
    unless instance_variable_defined? :@self_and_descendant_set
      self_and_descendant_set = Set.new
      self_and_descendant_set.add self

      child_set.each do |child|
        self_and_descendant_set.merge child.self_and_descendant_set
      end

      @self_and_descendant_set = self_and_descendant_set
    end

    @self_and_descendant_set
  end
end