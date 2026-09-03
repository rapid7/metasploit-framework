# frozen_string_literal: true

require 'spec_helper'
require 'rex/post/meterpreter/ui/console/meterpreter_alias_configuration'
require 'tempfile'

RSpec.describe Rex::Post::Meterpreter::Ui::Console::MeterpreterAliasConfiguration do
  def load_yaml(yaml, module_validator: nil)
    Tempfile.create(['meterpreter-aliases', '.yml']) do |file|
      file.write(yaml)
      file.flush
      return described_class.load(path: file.path, module_validator: module_validator)
    end
  end

  let(:valid_yaml) do
    <<~YAML
      version: 1
      aliases:
        example:
          description: Run an example module
          platforms: [linux]
          module: post/linux/gather/enum_system
          positional:
            - option: TARGET_PATH
              required: true
          defaults:
            VERBOSE: false
          switches:
            "-x":
              description: Enable execution
              options:
                EXECUTE: true
          architecture_options:
            source: sysinfo
            values:
              aarch64:
                TARGET: 2
    YAML
  end

  it 'normalizes and freezes valid YAML' do
    configuration = load_yaml(valid_yaml)

    expect(configuration['aliases']['example']['architecture_options']['values']['aarch64']['TARGET']).to eq(2)
    expect(configuration).to be_frozen
    expect(configuration['aliases']['example']).to be_frozen
  end

  it 'accepts hyphenated alias names' do
    configuration = load_yaml(valid_yaml.sub('example:', 'execute-assembly:'))

    expect(configuration['aliases']).to include('execute-assembly')
  end

  it 'rejects unavailable modules' do
    expect do
      load_yaml(valid_yaml, module_validator: ->(_module_name) { false })
    end.to raise_error(described_class::Error, /module is unavailable or unsupported/)
  end

  it 'rejects unknown keys with alias context' do
    expect do
      load_yaml(valid_yaml.sub('platforms: [linux]', "platforms: [linux]\n    arbitrary: true"))
    end.to raise_error(described_class::Error, /Alias 'example'.*unknown key: arbitrary/)
  end

  it 'rejects YAML object deserialization' do
    expect do
      load_yaml("--- !ruby/object:Object {}\n")
    end.to raise_error(described_class::Error, /Unable to parse Meterpreter alias configuration/)
  end
end
