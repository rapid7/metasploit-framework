module Metasploit::Framework::Scoped::Synchronization::Platform
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

  def added_platforms
    unless instance_variable_defined? :@added_platforms
      if added_attributes_set.empty?
        @added_platforms = []
      else
        @added_platforms = Mdm::Platform.where(
            # AREL cannot visit Set
            fully_qualified_name: added_attributes_set.to_a
        )
      end
    end

    @added_platforms
  end

  def build_added
    added_platforms.each do |platform|
      associated.build(
          platform: platform
      )
    end
  end

  def destination_attributes_set
    unless instance_variable_defined? :@destination_attributes_set
      if destination.new_record?
        @destination_attributes_set = Set.new
      else
        @destination_attributes_set = scope.each_with_object(Set.new) { |join, set|
          set.add join.platform.fully_qualified_name
        }
      end
    end

    @destination_attributes_set
  end

  def destroy_removed
    unless destination.new_record? || removed_attributes_set.empty?
      scope.where(
          Mdm::Platform.arel_table[:fully_qualified_name].in(
              # AREL cannot visit Set
              removed_attributes_set.to_a
          )
      ).destroy_all
    end
  end

  def scope
    associated.joins(:platform)
  end

  def source_attributes_set
    @source_attributes_set ||= source_platform_list.platforms.each_with_object(Set.new) { |metasploit_framework_platform, set|
      set.add metasploit_framework_platform.fully_qualified_name
    }
  end

  def source_platform_list
    if source.respond_to? :platform_list
      source.platform_list
    else
      module_instance = scope_module_instance(destination)
      location = module_instance_location(module_instance)

      elog(
          "In #{location}:\n" \
          "#{source} does not respond to platform_list"
      )

      Msf::Module::PlatformList.new
    end
  end
end