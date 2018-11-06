# {ClassMethods#visit DSL} to declare {Metasploit::Model::Visitation::Visitor visitors} for a given `Module#name`
# (or any Class that has an ancestor in `Class#ancestors` with that `Module#name`) and then use then to {#visit}
# instances of those class and/or modules.
module Metasploit::Model::Visitation::Visit
  extend ActiveSupport::Concern

  # Adds {#visit} DSL to class to declare {Metasploit::Model::Visitation::Visitor visitors}.
  module ClassMethods
    # Defines how to visit a node with one or more `Module#names` in its `Module#ancestors`.
    #
    # @param module_names [Array<String>] Names of class/module to be visited with block.
    # @yield [node] Block instance_exec'd on instance of the class {#visit} was called.
    # @yieldparam node [Object]
    # @return [Array<Metasploit::Model::Visitation::Visitor>] visitors created.
    # @raise [ArgumentError] if `module_names` is empty
    # @raise [Metasploit::Model::Invalid] unless `block` is given.
    def visit(*module_names, &block)
      if module_names.empty?
        raise ArgumentError,
              "At least one Modul#name must be passed to #{__method__} so the visitor(s) knows which Modules " \
                    "it/they can visit."
      end

      module_names.collect do |module_name|
        visitor = Metasploit::Model::Visitation::Visitor.new(
            :module_name => module_name,
            :parent => self,
            &block
        )
        visitor.valid!

        visitor_by_module_name[visitor.module_name] = visitor
      end
    end

    # {Metasploit::Model::Visitation::Visitor Visitor} for `klass` or one of its `Class#ancestors`.
    #
    # @return [Metasploit::Model::Visitation::Visitor]
    # @raise [TypeError] if there is not visitor for `klass` or one of its ancestors.
    def visitor(klass)
      visitor = visitor_by_module[klass]

      unless visitor
        klass.ancestors.each do |mod|
          visitor = visitor_by_module[mod]

          unless visitor
            visitor = visitor_by_module_name[mod.name]
          end

          if visitor
            visitor_by_module[klass] = visitor

            break
          end
        end
      end

      unless visitor
        raise TypeError,
              "No visitor that handles #{klass} or " \
                    "any of its ancestors (#{klass.ancestors.map(&:name).to_sentence})"
      end

      visitor
    end

    # Allows {Metasploit::Model::Visitation::Visitor visitors} to be looked up by Module instead of `Module#name`.
    #
    # @return [Hash{Class => Metasploit::Model::Visitation::Visitor}]
    def visitor_by_module
      @visitor_by_module ||= {}
    end

    # Maps `Module#name` passed to {ClassMethods#visit} through :module_name to the
    # {Metasploit::Model::Visitation::Visitor} with the `Module#name` as
    # {Metasploit::Model::Visitation::Visitor#module_name}.
    #
    # @return [Hash{String => Metasploit::Model::Visitation::Visitor}]
    def visitor_by_module_name
      @visitor_by_module_name ||= {}
    end
  end

  #
  # Instance Methods
  #

  # Visits `node`
  #
  # @return (see Metasploit::Model::Visitation::Visitor#visit)
  def visit(node)
    visitor = self.class.visitor(node.class)

    visitor.visit(self, node)
  end
end
