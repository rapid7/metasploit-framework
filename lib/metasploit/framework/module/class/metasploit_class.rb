require 'weakref'

module Metasploit::Framework::Module::Class::MetasploitClass
  extend Metasploit::Framework::ResurrectingAttribute

  #
  # Resurrecting Attributes
  #

  # @!attribute [rw] module_class
  #   Cached metadata for this Class.
  #
  #   @return [Metasploit::Model::Module::Class]
  resurrecting_attr_accessor :module_class do
    ActiveRecord::Base.connection_pool.with_connection {
      ActiveRecord::Base.transaction {
        module_ancestors = []
        module_class_sets = []

        each_module_ancestor do |module_ancestor|
          # for Mdm::Module::Class.new
          module_ancestors << module_ancestor
          # for Mdm::Module::Class.find_by_sql
          module_class_sets << module_ancestor.descendants
        end

        module_class_intersection = module_class_sets.inject { |intersection, module_class_set|
          intersection.intersect module_class_set
        }
        module_class_intersection_sql = module_class_intersection.to_sql
        strong_reference = Mdm::Module::Class.find_by_sql(module_class_intersection_sql).first

        unless strong_reference
          strong_reference = Mdm::Module::Class.new(ancestors: module_ancestors)
        end

        strong_reference
      }
    }
  end

  #
  # Methods
  #

  # @note It is the caller's responsibility to check that returned `Metasploit::Model::Module::Class` saved
  #   successfully.
  #
  # Caches class metadata.
  #
  # @param module_class [Metasploit::Model::Module::Class, nil] module class to which to write metadata.  If `nil`,
  #   write metadata to {#module_class}.
  # @return [Metasploit::Model::Module::Class]
  def cache_module_class(module_class=nil)
    module_class ||= self.module_class

    ActiveRecord::Base.connection_pool.with_connection do
      cache_rank(module_class)
      module_class.save
    end

    module_class
  end

  # @note `module_class` is not saved after `Metasploit::Model::Module::Class#rank` is set.  Use {#cache_module_class}
  #   to set rank and save.
  #
  # Caches `#rank_name` in `module_class` `Metasploit::Model::Module::Class#rank`.
  #
  # @param module_class [Metasploit::Model::Module::Class] module class to which to write rank metadata.
  # @return [void]
  def cache_rank(module_class)
    ActiveRecord::Base.connection_pool.with_connection do
      begin
        name = self.rank_name
      rescue Exception
        # module author forgot to define method or forgot to subclass Msf::Module
      else
        rank = Mdm::Module::Rank.where(name: name).first
        module_class.rank = rank
      end
    end
  end

  def each_module_ancestor
    unless block_given?
      to_enum(__method__)
    else
      ancestors.each do |ancestor|
        if ancestor.respond_to? :module_ancestor
          yield ancestor.module_ancestor
        end
      end
    end
  end
end
