# -*- coding:binary -*-
require 'spec_helper'
require 'rex/file'

RSpec.describe Msf::Modules::Loader::Executable do
  include_context 'Msf::Modules::Loader::Base'

  let(:module_manager) do
    instance_double(Msf::ModuleManager)
  end

  let(:module_path) do
    "#{parent_path}/#{type}/#{module_reference_name}.go"
  end

  let(:type) do
    'auxiliary'
  end

  subject do
    described_class.new(module_manager)
  end

  describe '#read_script_env_runtime' do
    [
      {
        value: '//usr/bin/env go run "$0" "$@"; exit "$?"',
        expected: 'go'
      },
      { value: '#!/usr/bin/env python3', expected: 'python3' },
      { value: '#!/usr/bin/env ruby', expected: 'ruby' },
      # Not supported; Might need to be supported in the future
      { value: '#!/usr/bin/python3', expected: nil },
      { value: '#!/usr/bin/ruby', expected: nil },
      { value: '', expected: nil },
    ].each do |test|
      it "detects #{test[:value].inspect} as #{test[:expected]}" do
        path = 'mock_path'
        allow(File).to receive(:open).and_call_original
        allow(File).to receive(:open).with(path, 'rb') do |&block|
          block.call StringIO.new(test[:value])
        end
        expect(subject.send(:read_script_env_runtime, path)).to eq test[:expected]
      end
    end
  end

  describe '#loadable_module?' do
    context 'when the language runtime is not available' do
      let(:module_reference_name) do
        'scanner/msmail/non_existent_module'
      end

      let(:module_content) do
        <<~EOF.strip
          //usr/bin/env go run "$0" "$@"; exit "$?"
          
          package main 
        EOF
      end

      let(:temp_file) do
        Tempfile.new.tap do |f|
          f.write(module_content)
          f.flush
        end
      end

      let(:module_path) do
        temp_file.path
      end

      before(:example) do
        allow(subject).to receive(:module_path).with(parent_path, type, module_reference_name).and_return(module_path)
        allow(File).to receive(:executable?).with(module_path).and_return(true)
        expect(::Rex::FileUtils).to_not receive(:find_full_path)
      end

      it 'should return true - even though the runtime is not supported, so that later read_module_content can return a human readable error' do
        expect(subject.loadable_module?(parent_path, type, module_reference_name)).to be(true)
      end
    end
  end

  describe '#read_module_content' do
    context 'with non-existent module_path' do
      let(:module_reference_name) do
        'scanner/msmail/non_existent_module'
      end

      before(:example) do
        allow(subject).to receive(:load_error).with(module_path, kind_of(Errno::ENOENT))
        allow(subject).to receive(:module_path).with(parent_path, type, module_reference_name).and_return(module_path)
      end

      # this ensures that the File.exist?(module_path) checks are checking the same path as the code under test
      it 'should attempt to open the expected module_path' do
        expect(File.exist?(module_path)).to be_falsey

        subject.send(:read_module_content, parent_path, type, module_reference_name)
      end

      it 'should not raise an error' do
        expect {
          subject.send(:read_module_content, parent_path, type, module_reference_name)
        }.to_not raise_error
      end

      it 'should return an empty string' do
        expect(subject.send(:read_module_content, parent_path, type, module_reference_name)).to eq ''
      end

      it 'should record the load error' do
        expect(subject).to receive(:load_error).with(module_path, kind_of(Errno::ENOENT))

        expect(subject.send(:read_module_content, parent_path, type, module_reference_name)).to eq ''
      end
    end

    context 'when the language runtime is not available' do
      let(:module_reference_name) do
        'scanner/msmail/non_existent_module'
      end

      let(:module_content) do
        <<~EOF.strip
          //usr/bin/env go run "$0" "$@"; exit "$?"
          
          package main 
        EOF
      end

      let(:temp_file) do
        Tempfile.new.tap do |f|
          f.write(module_content)
          f.flush
        end
      end

      let(:module_path) do
        temp_file.path
      end

      before(:example) do
        allow(subject).to receive(:load_error).with(module_path, RuntimeError.new("Unable to load module as the following runtime was not found on the path: go"))
        allow(subject).to receive(:module_path).with(parent_path, type, module_reference_name).and_return(module_path)
        allow(File).to receive(:executable?).with(module_path).and_return(true)
        expect(::Rex::FileUtils).to receive(:find_full_path).with('go').and_return(false)
      end

      it 'should not raise an error' do
        expect {
          subject.send(:read_module_content, parent_path, type, module_reference_name)
        }.to_not raise_error
      end

      it 'should return an empty string' do
        expect(subject.send(:read_module_content, parent_path, type, module_reference_name)).to eq ''
      end

      it 'should record the load error' do
        expect(subject).to receive(:load_error).with(module_path, RuntimeError.new("Unable to load module as the following runtime was not found on the path: go"))

        expect(subject.send(:read_module_content, parent_path, type, module_reference_name)).to eq ''
      end
    end
  end
end
