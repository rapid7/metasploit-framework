FactoryGirl.define do
  klass = Msf::Simple::Framework

  factory :msf_simple_framework,
          class: klass,
          traits: [
              :metasploit_model_base,
              :msf_framework_attributes
          ] do
    # dont' call a proc by default
    on_create_proc { nil }
    config_directory { Msf::Config::Defaults['ConfigDirectory'] }
    defer_module_loads { true }

    initialize_with {
      # anything besides new must be called explicitly on the Class
      klass.create(
          'ConfigDirectory' => attributes[:config_directory],
          'DeferModuleLoads' => attributes[:defer_module_loads],
          'OnCreateProc' => attributes[:on_create_proc]
      )
    }
  end
end