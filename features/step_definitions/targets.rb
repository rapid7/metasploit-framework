When /^targets are loaded$/ do
  config_file = File.expand_path('features/support/targets.yml')
  fail "Target config file #{config_file} does not exist" unless File.exists?(config_file)
  @target_config = YAML.load_file(config_file)
end

When /^(RHOSTS?) (?:are|is) (\S+)$/ do |type, target_type|
  fail "No target type #{target_type}" unless @target_config.key?(target_type)
  step "I type \"set #{type} #{@target_config[target_type]}\""
end
