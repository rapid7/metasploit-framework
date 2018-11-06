# Loads ActiveSupport::Concerns (or anything that can be passed to `include` really) under {#root}
class Metasploit::Concern::Loader
  include ActiveModel::Validations

  #
  # Attributes
  #

  # @!attribute [rw] root
  #   Pathname under which to find concerns.
  #
  #   @return [Pathname]
  attr_accessor :root

  #
  # Validations
  #

  validates :root,
            presence: true

  #
  # Methods
  #

  # Yields each constant under `parent_pathname`.
  #
  # @param mechanism [:constantize, :require] `:require` if child pathname should be required so that the constant
  #   cannot be unloaded by `ActiveSupport::Dependencies.clear`.
  # @param parent_pathname [Pathname]
  # @yield [constant]
  # @yieldparam constant [Module] constant declared under `parent_pathname`.
  # @yieldreturn [void]
  # @return [void]
  def each_pathname_constant(mechanism:, parent_pathname:)
    parent_pathname.each_child do |child_pathname|
      constant = constantize_pathname(
          mechanism: mechanism,
          pathname: child_pathname
      )

      if constant
        yield constant
      end
    end
  end

  # Glob pattern for concerns.
  #
  # @return [Pathname]
  def glob
    root.join('**', '*.rb')
  end

  # @param attributes [Hash{Symbol => String,nil}]
  def initialize(attributes={})
    attributes.each do |attribute, value|
      public_send("#{attribute}=", value)
    end
  end

  # Set of Pathnames for `Module`s that will have concerns included.
  #
  # @return [Set<Pathname>]
  def module_pathname_set
    concern_paths = Dir.glob(glob)

    concern_paths.each_with_object(Set.new) { |concern_path, module_pathname_set|
      concern_pathname = Pathname.new(concern_path)
      module_pathname = concern_pathname.parent

      module_pathname_set.add module_pathname
    }
  end

  # Registers load hooks with `ActiveSupport.on_load`.
  #
  # @return [void]
  def register
    module_pathname_set.each do |module_pathname|
      relative_module_pathname = module_pathname.relative_path_from(root)
      relative_module_path = relative_module_pathname.to_path
      underscored_module_name = relative_module_path.gsub(File::SEPARATOR, '_')
      on_load_name = underscored_module_name.to_sym

      # on_load block is instance_evaled, so need to capture self
      loader = self

      ActiveSupport.on_load(on_load_name) do
        if ActiveSupport::Dependencies.autoloaded? self
          mechanism = :constantize
        else
          mechanism = :require
        end

        loader.each_pathname_constant(mechanism: mechanism, parent_pathname: module_pathname) do |concern|
          include concern
        end
      end
    end
  end

  private

  # Converts `descendant_pathname`, which should be under {#root}, into a constant.
  #
  # @param mechanism [:constantize, :require] `:require` if pathname should be required so that the constant cannot be
  #   unloaded by `ActiveSupport::Dependencies.clear`.
  # @param pathname [Pathname] a Pathname under {#root}.
  # @return [Object] if {#pathname_to_constant_name} returns a constant name
  # @return [nil] otherwise
  def constantize_pathname(mechanism:, pathname:)
    constant_name = pathname_to_constant_name(pathname)

    constant = nil

    if constant_name
      # require before calling constantize so that the constant isn't recorded as unloadable.
      if mechanism == :require
        require pathname
      end

      # constantize either way as the the constant_name still needs to be converted to Module
      constant = constant_name.constantize
    end

    constant
  end

  # Converts `descendant_pathname`, which should be under {#root}, into a constant name.
  #
  # @param descendant_pathname [Pathname] a Pathname under {#root}.
  def pathname_to_constant_name(descendant_pathname)
    extension_name = descendant_pathname.extname
    constant_name = nil

    if extension_name == '.rb'
      constant_pathname = descendant_pathname.relative_path_from(root)
      constant_name = constant_pathname.to_s.gsub(/.rb$/, '').camelize
    end

    constant_name
  end
end