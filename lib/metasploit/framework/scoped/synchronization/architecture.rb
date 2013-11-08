module Metasploit::Framework::Scoped::Synchronization::Architecture
  extend ActiveSupport::Concern

  include Metasploit::Framework::Module::Instance::Logging

  included do
    self.join_association = self.name.demodulize.underscore.to_sym

    synchronize do
      destroy_removed
      build_added
    end
  end

  module ClassMethods
    attr_accessor :join_association
  end

  #
  # Instance Methods
  #

  def associated
    destination.send(self.class.join_association)
  end

  def added_architectures
    @added_architectures ||= Mdm::Architecture.where(
        # AREL cannot visit Set
        abbreviation: added_attributes_set.to_a
    )
  end

  def build_added
    added_architectures.each do |architecture|
      associated.build(
          architecture: architecture
      )
    end
  end

  def destination_attributes_set
    @destination_attributes_set ||= scope.each_with_object(Set.new) { |join, set|
      set.add join.architecture.abbreviation
    }
  end

  def destroy_removed
    scope.where(
        Mdm::Architecture.arel_table[:abbreviation].in(
            # AREL cannot visit Set
            removed_attributes_set.to_a
        )
    ).destroy_all
  end

  def scope
    associated.joins(:architecture)
  end

  def source_architecture_abbreviations
    begin
      source.architecture_abbreviations
    rescue NoMethodError => error
      case destination
        when Metasploit::Model::Module::Instance
          module_instance = destination
        when Metasploit::Model::Module::Target
          module_instance = destination.module_instance
        else
          raise ArgumentError, "Can't extract Module::Instance from #{destination.class}"
      end

      log_module_instance_error(module_instance, error)

      []
    end
  end

  def source_attributes_set
    @source_attributes_set ||= Set.new source_architecture_abbreviations
  end
end