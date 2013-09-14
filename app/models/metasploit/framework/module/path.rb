# In-memory equivalent of `Mdm::Module::Path`
class Metasploit::Framework::Module::Path < Metasploit::Model::Base
  extend ActiveModel::Callbacks
  include ActiveModel::Dirty
  include Metasploit::Model::Module::Path

  # Error raise by {Metasploit::Framework::Module::Path}.
  class Error < Metasploit::Framework::Error

  end

  #
  # Attributes Methods - used to track changed attributes
  #

  define_attribute_method :gem
  define_attribute_method :name
  define_attribute_method :real_path

  #
  # Attributes
  #

  # @!attribute [rw] gem
  #   The name of the gem that is adding this module path to
  #   metasploit-framework.  For paths normally added by
  #   metasploit-framework itself, this would be `'metasploit-framework'`,
  #   while for Metasploit Pro this would be `'metasploit-pro'`.  The name
  #   used for `gem` does not have to be a gem on rubygems, it just
  #   functions as a namespace for {#name} so that projects using
  #   metasploit-framework do not need to worry about collisions on
  #   {#name} which could disrupt the cache behavior.
  #
  #   @return [String]
  attr_reader :gem

  # @!attribute [rw] name
  #   The name of the module path scoped to {#gem}.  {#gem} and {#name}
  #   uniquely identify this path so that if {#real_path} changes, the
  #   entire cache does not need to be invalidated because the change in
  #   {#real_path} will still be tied to the same ({#gem}, {#name}) tuple.
  #
  #   @return [String]
  attr_reader :name

  # @!attribute [rw] real_path
  #   @note Non-real paths will be converted to real paths in a before
  #   validation callback, so take care to either pass real paths or pay
  #   attention when setting {#real_path} and then changing directories
  #   before validating.
  #
  #   The real (absolute) path to module path.
  #
  #   @return [String]
  attr_reader :real_path

  #
  # Callbacks
  #

  define_model_callbacks :save

  after_save :update_module_ancestor_real_paths

  #
  # Methods
  #

  # Updates {#gem} value and marks {#gem} as changed if `gem` differs from
  # {#gem}.
  #
  # @param gem [String, nil] (see #gem)
  # @return [String, nil] `gem`
  def gem=(gem)
    unless gem == @gem
      gem_will_change!
    end

    @gem = gem
  end

  # @param attributes [Hash{Symbol => String}]
  # @option attributes [String, nil] :gem (see #gem)
  # @option attributes [String, nil] :name (see #name)
  # @option attributes [String] :real_path (see #real_path)
  def initialize(attributes={})
    attributes.each do |attribute, value|
      public_send("#{attribute}=", value)
    end
  end

  # The modules ancestors that use this as a
  # {Metasploit::Framework::Module::Ancestor#parent_path}.
  #
  # @return [Array<Metasploit::Framework::Module::Ancestor>]
  def module_ancestors
    @module_ancestors ||= []
  end

  # Updates {#name} value and marks {#name} as changed if `name` differs
  # from {#name}.
  #
  # @param name [String, nil] (see #name)
  # @return [String, nil] `name`
  def name=(name)
    unless name == @name
      name_will_change!
    end

    @name = name
  end

  # @note This path should be validated before calling
  #   {#name_collision} so that {#gem} and {#name} is normalized.
  #
  # Returns path in {#path_set} with the same {#gem} and {#name}.
  #
  # @return [Metasploit::Framework::Module::Path] if there is a
  #   {Metasploit::Framework::Module::Path} with the same {#gem} and
  #   {#name} as this path.
  # @return [nil] if #named? is `false`.
  # @return [nil] if there is not match.
  # @raise (see #path_set)
  def name_collision
    collision = nil

    # Don't check path_by_name_by_gem if gem and name are nil since
    # path_by_name_by_gem doesn't support nils.
    if named?
      path_by_name = path_set.path_by_name_by_gem[gem]
      collision = path_by_name[name]
    end

    collision
  end

  # Sets {#path_set}.
  #
  # @param path_set [Metasploit::Framework::Module::PathSet::Memory] the
  #   path_set to which this path belongs.
  # @return [Metasploit::Framework::Module::PathSet::Memory] `path_set`
  # @raise [Metasploit::Framework::Module::Path::Error] if path_set has
  #   not already been set.
  def path_set=(path_set)
    if instance_variable_defined? :@path_set
      raise Metasploit::Framework::Module::Path::Error,
            'already associated with another Metasploit::Framework::Module::PathSet::Memory'
    end

    @path_set = path_set
  end

  # The set of path to which this path
  # belongs.  The path set is used to calculate {#name_collision} and
  # {#real_path_collision}.  The path_set is also updated when this
  # path is {#save! saved}.
  #
  # @return [Metasploit::Framework::Module::PathSet::Memory]
  def path_set
    unless instance_variable_defined? :@path_set
      raise Metasploit::Framework::Module::Path::Error,
            'path_set not set prior to use'
    end

    @path_set
  end

  # Updates {#real_path} value and marks {#real_path} as changed if
  # `real_path` differs from {#real_path}.
  #
  # @param real_path [String, nil] (see #real_path)
  # @return [String, nil] `real_path`
  def real_path=(real_path)
    unless real_path == @real_path
      real_path_will_change!
    end

    @real_path = real_path
  end

  # @note This path should be validated before calling
  #   {#real_path_collision} so that {#real_path} is normalized.
  #
  # Returns path in {#path_set} with the same {#real_path}.
  #
  # @return [Metasploit::Framework::Module::Path] if there is a
  #   {Metasploit::Framework::Module::Path} with the same {#real_path} as
  #   this path.
  # @return [nil] if there is not match.
  # @raise (see #path_set)
  def real_path_collision
    path_set.path_by_real_path[real_path]
  end

  # Saves this path to {#path_set}.
  #
  # @return [void]
  # @raise [Metasploit::Framework::ModuleInvalid] if this path is invalid.
  def save!
    valid!
    unless valid?
      raise Metasploit::Framework::ModelInvalid.new(self)
    end

    run_callbacks :save do
      if gem_changed? or name_changed?
        if was_named?
          path_by_name = path_set.path_by_name_by_gem[gem_was]
          path_by_name.delete(name_was)
        end

        if named?
          path_by_name = path_set.path_by_name_by_gem[gem]
          path_by_name[name] = self
        end
      end

      if real_path_changed?
        unless real_path_was.nil?
          path_set.path_by_real_path.delete(real_path_was)
        end

        path_set.path_by_real_path[real_path] = self
      end
    end

    # reset changes after running callbacks so they can use
    # <attribute>_changed?
    @previously_changed = changes
    @changed_attributes.clear
  end

  # If {#real_path} changes, then update the
  # {Metasploit::Framework::Module::Ancestor#real_path} for
  # {#module_ancestors}.
  #
  # @return [void]
  def update_module_ancestor_real_paths
    if real_path_changed?
      module_ancestors.each do |module_ancestor|
        # @todo update Metasploit::Framework::AncestorSet instance
        module_ancestor.real_path = module_ancestor.derived_real_path
      end
    end
  end
end
