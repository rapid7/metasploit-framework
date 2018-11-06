# Visits node in a {http://en.wikipedia.org/wiki/Tree_(data_structure) tree}, such as
# {Metasploit::Model::Search::Query#tree}.
class Metasploit::Model::Visitation::Visitor < Metasploit::Model::Base
  #
  # Attributes
  #

  # @!attribute [rw] block
  #   Block that is instance_exec'd on instance of {#parent} and passed the node to visit.
  #
  #   @return [Proc]
  attr_accessor :block

  # @!attribute [rw] module_name
  #   Name of `Module` (or `Class`) that can be visited by this visitor.  This visitor is also assumed to be able to
  #   {#visit} any `Class` or `Module` that has the `Module` or `Class` with `module_name` as a `Module#ancestor`.
  #
  #   @return [String]
  attr_accessor :module_name

  # @!attribute [rw] parent
  #   The `Class` on which this visitor was created.
  #
  #   @return [Class]
  attr_accessor :parent

  #
  # Validations
  #

  validates :block,
            :presence => true
  validates :module_name,
            :presence => true
  validates :parent,
            :presence => true

  #
  # Methods
  #

  # @param attributes [Hash{Symbol => Object}]
  # @option attributes [String] :module_name name of module (or class) that can be visited by this visitor.
  # @option attributes [Class] :parent The `Class` on which {Metasploit::Model::Visitation::Visit::ClassMethods#visit}
  #   was called.
  # @yield [node] Block instance_exec'd on instance of :parent class.
  # @yieldparam node [Object] node being {Metasploit::Model::Visitation::Visit#visit visited}.
  # @yieldreturn [Object] translation of `node`.
  def initialize(attributes={}, &block)
    attributes.assert_valid_keys(:module_name, :parent)

    @block = block
    super
  end

  # Visit `node` with {#block} instance_exec'd on `instance`.
  #
  # @param instance [Object] instance of {#parent}.
  # @param node [Object] node being visited.
  # @return [Object]
  # @raise [TypeError] if `instance` is not a {#parent}.
  def visit(instance, node)
    unless instance.is_a? parent
      raise TypeError, "#{instance} is not an instance of #{parent}, so it cannot be visited."
    end

    instance.instance_exec(node, &block)
  end
end