# -*- coding:binary -*-
require 'spec_helper'
require 'msf/core'
require 'msf/core/modules/loader/directory'

require 'msf/core'

RSpec.describe Msf::Modules::Loader::Directory do
  context 'instance methods' do
    include_context 'Msf::Modules::Loader::Base'

    let(:module_manager) do
      double('Module Manager')
    end

    let(:module_path) do
      "#{parent_path}/exploits/#{module_reference_name}.rb"
    end

    let(:type) do
      'exploit'
    end

    subject do
      described_class.new(module_manager)
    end

    context '#load_module' do
      context 'with existent module_path' do
        include_context 'Metasploit::Framework::Spec::Constants cleaner'

        let(:framework) do
          framework = double('Msf::Framework', :datastore => {})

          events = double('Events')
          allow(events).to receive(:on_module_load)
          allow(events).to receive(:on_module_created)
          allow(framework).to receive(:events).and_return(events)

          framework
        end

        let(:module_full_name) do
          "#{type}/#{module_reference_name}"
        end

        let(:module_manager) do
          Msf::ModuleManager.new(framework)
        end

        let(:module_reference_name) do
          'windows/smb/ms08_067_netapi'
        end

        it 'should load a module that can be created' do
          expect(subject.load_module(parent_path, type, module_reference_name)).to be_truthy

          created_module = module_manager.create(module_full_name)

          expect(created_module.name).to eq 'MS08-067 Microsoft Server Service Relative Path Stack Corruption'
        end

        context 'with module previously loaded' do
          before(:example) do
            subject.load_module(parent_path, type, module_reference_name)
          end

          # Payloads are defined as ruby Modules so they can behave differently
          context 'with payload' do
            let(:reference_name) do
              'stages/windows/x64/vncinject'
            end

            let(:type) do
              'payload'
            end

            it 'should not load the module' do
              expect(subject.load_module(parent_path, type, module_reference_name)).to be_falsey
            end
          end

          # Non-payloads are defined as ruby Classes
          context 'without payload' do
            let(:reference_name) do
              'windows/smb/ms08_067_netapi'
            end

            let(:type) do
              'exploit'
            end

            it 'should not load the module' do
              expect(subject.load_module(parent_path, type, module_reference_name)).to be_falsey
            end
          end
        end
      end

      context 'without existent module_path' do
        let(:module_reference_name) do
          'osx/armle/safari_libtiff'
        end

        let(:error) do
          Errno::ENOENT.new(module_path)
        end

        before(:example) do
          allow(module_manager).to receive(:file_changed?).and_return(true)
          allow(module_manager).to receive(:module_load_error_by_path).and_return({})
        end

        it 'should not raise an error' do
          expect(File.exist?(module_path)).to be_falsey

          expect {
            subject.load_module(parent_path, type, module_reference_name)
          }.to_not raise_error
        end

        it 'should return false' do
          expect(File.exist?(module_path)).to be_falsey

          expect(subject.load_module(parent_path, type, module_reference_name)).to be_falsey
        end
      end
    end

    context '#read_module_content' do
      context 'with non-existent module_path' do
        let(:module_reference_name) do
          'osx/armle/safari_libtiff'
        end

        before(:example) do
          allow(subject).to receive(:load_error).with(module_path, kind_of(Errno::ENOENT))
        end

        # this ensures that the File.exist?(module_path) checks are checking the same path as the code under test
        it 'should attempt to open the expected module_path' do
          expect(File).to receive(:open).with(module_path, 'rb')
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
    end
  end
end
