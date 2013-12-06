module Metasploit::Framework::Scoped::Synchronization::Architecture
  extend ActiveSupport::Concern

  include Metasploit::Framework::Scoped::Logging

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
    unless instance_variable_defined? :@added_architectures
      if added_attributes_set.empty?
        @added_architectures = []
      else
        @added_architectures = Mdm::Architecture.where(
            # AREL cannot visit Set
            abbreviation: added_attributes_set.to_a
        )
      end
    end

    @added_architectures
  end

  def build_added
    added_architectures.each do |architecture|
      associated.build(
          architecture: architecture
      )
    end
  end

  def destination_attributes_set
    unless instance_variable_defined? :@destination_attributes_set
      if destination.new_record?
        @destination_attributes_set = Set.new
      else
        @destination_attributes_set = scope.each_with_object(Set.new) { |join, set|
          set.add join.architecture.abbreviation
        }
      end
    end

    @destination_attributes_set
  end

  def destroy_removed
    unless destination.new_record? || removed_attributes_set.empty?
      scope.where(
          Mdm::Architecture.arel_table[:abbreviation].in(
              # AREL cannot visit Set
              removed_attributes_set.to_a
          )
      ).destroy_all
    end
  end

  def scope
    associated.joins(:architecture)
  end

  def source_architecture_abbreviations
    begin
      source.architecture_abbreviations
    rescue NoMethodError => error
      log_scoped_error(destination, error)

      []
    end
  end

  def source_attributes_set
    @source_attributes_set ||= Set.new source_architecture_abbreviations
  end
end