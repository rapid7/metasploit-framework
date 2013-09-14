FactoryGirl.define do
  factory :metasploit_framework_module_path_load,
          class: Metasploit::Framework::Module::Path::Load,
          traits: [
              :metasploit_model_base
          ]  do
    #
    # Associations
    #

    association :cache, factory: :metasploit_framework_module_cache
    association :module_path, factory: :mdm_module_path

    #
    # Attributes
    #

    changed { generate :metasploit_framework_module_path_load_changed }
  end

  changed = [false, true]
  sequence :metasploit_framework_module_path_load_changed, changed.cycle
end