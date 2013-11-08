module Metasploit::Framework::Scoped::Synchronization::Platform
  extend ActiveSupport::Concern

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
    @added_platforms ||= Mdm::Platform.where(
        # AREL cannot visit Set
        fully_qualified_name: added_attributes_set.to_a
    )
  end

  def build_added
    added_platforms.each do |platform|
      associated.build(
          platform: platform
      )
    end
  end

  def destination_attributes_set
    @destination_attributes_set ||= scope.each_with_object(Set.new) { |join, set|
      set.add join.platform.fully_qualified_name
    }
  end

  def destroy_removed
    scope.where(
        Mdm::Platform.arel_table[:fully_qualified_name].in(
            # AREL cannot visit Set
            removed_attributes_set.to_a
        )
    ).destroy_all
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
    begin
      source.platform_list
    rescue NoMethodError => error
      log_module_instance_error(destination, error)

      Msf::Module::PlatformList.new
    end
  end
end