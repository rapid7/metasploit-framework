# Synchronizes {#metasploit_instance metasploit instance's} {Msf::Module::HasActions#actions actions} to
# {#module_instance} `Metasploit::Model::Module::Instance#module_actions`.
class Metasploit::Framework::Module::Instance::Synchronization::Actions < Metasploit::Framework::Module::Instance::Synchronization::Base
  #
  # CONSTANTS
  #

  # Only actions are required
  ALLOW_BY_ATTRIBUTE = {
      actions: true
  }

  #
  # Synchronization
  #

  synchronize do
    destroy_removed
    build_added
    update_default_action
  end

  #
  # Methods
  #

  def build_added
    added_attributes_set.each do |name|
      destination.actions.build(
          name: name
      )
    end
  end

  def destination_attributes_set
    @destination_attribute_set = Set.new scope.pluck(:name)
  end

  def destroy_removed
    scope.where(
        # AREL cannot visit Set
        name: removed_attributes_set.to_a
    ).destroy_all
  end

  def scope
    destination.actions
  end

  def source_actions
    begin
      source.actions
    rescue NoMethodError => error
      log_module_instance_error(destination, error)

      []
    end
  end

  def source_attributes_set
    @source_attributes_set ||= source_actions.each_with_object(Set.new) { |msf_module_auxiliary_action, set|
      set.add msf_module_auxiliary_action.name
    }
  end

  def source_default_action
    begin
      source.default_action
    rescue NoMethodError => error
      log_module_instance_error(destination, error)

      nil
    end
  end

  def update_default_action
    default_action_name = source_default_action

    if default_action_name
      destination.actions.each do |action|
        if action.name == default_action_name
          destination.default_action = action

          break
        end
      end
    end
  end
end