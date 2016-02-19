# -*- coding:binary -*-
require 'spec_helper'

require 'msf/core'
require 'msf/core/modules/namespace'

RSpec.describe Msf::Modules::Namespace do
  let(:module_path) do
    "parent/path/type_directory/#{module_reference_name}.rb"
  end

  let(:module_reference_name) do
    'module/reference/name'
  end

  subject do
    mod = Module.new
    mod.extend described_class

    mod
  end

  context 'metasploit_class' do
    before(:example) do
      if major
        subject.const_set("Metasploit#{major}", Class.new)
      end
    end

    context 'without Metasploit<n> constant defined' do
      let(:major) do
        nil
      end

      it 'should not be defined' do
        metasploit_constants = subject.constants.select { |constant|
          constant.to_s =~ /Metasploit/
        }

        expect(metasploit_constants).to be_empty
      end
    end

    context 'with Metasploit1 constant defined' do
      let(:major) do
        1
      end

      it 'should be defined' do
        expect(subject.const_defined?('Metasploit1')).to be_truthy
      end

      it 'should return the class' do
        expect(subject.metasploit_class).to be_a Class
      end
    end

    context 'with Metasploit2 constant defined' do
      let(:major) do
        2
      end

      it 'should be defined' do
        expect(subject.const_defined?('Metasploit2')).to be_truthy
      end

      it 'should return the class' do
        expect(subject.metasploit_class).to be_a Class
      end
    end

    context 'with Metasploit3 constant defined' do
      let(:major) do
        3
      end

      it 'should be defined' do
        expect(subject.const_defined?('Metasploit3')).to be_truthy
      end

      it 'should return the class' do
        expect(subject.metasploit_class).to be_a Class
      end
    end

    context 'with Metasploit4 constant defined' do
      let(:major) do
        4
      end

      it 'should be defined' do
        expect(subject.const_defined?('Metasploit4')).to be_truthy
      end

      it 'should return the class' do
        expect(subject.metasploit_class).to be_a Class
      end
    end

    context 'with Metasploit5 constant defined' do
      let(:major) do
        5
      end

      it 'should be defined' do
        expect(subject.const_defined?('Metasploit5')).to be_truthy
      end

      it 'should be newer than Msf::Framework::Major' do
        expect(major).to be > Msf::Framework::Major
      end

      it 'should return nil' do
        expect(subject.metasploit_class).to be_nil
      end
    end
  end

  context 'metasploit_class!' do
    it 'should call metasploit_class' do
      expect(subject).to receive(:metasploit_class).and_return(Class.new)

      subject.metasploit_class!(module_path, module_reference_name)
    end

    context 'with metasploit_class' do
      let(:metasploit_class) do
        Class.new
      end

      before(:example) do
        allow(subject).to receive(:metasploit_class).and_return(metasploit_class)
      end

      it 'should return the metasploit_class' do
        expect(subject.metasploit_class!(module_path, module_reference_name)).to eq metasploit_class
      end
    end

    context 'without metasploit_class' do
      before(:example) do
        allow(subject).to receive(:metasploit_class)
      end

      it 'should raise a Msf::Modules::MetasploitClassCompatibilityError' do
        expect {
          subject.metasploit_class!(module_path, module_reference_name)
        }.to raise_error(Msf::Modules::MetasploitClassCompatibilityError)
      end

      context 'the Msf::Modules::MetasploitClassCompatibilityError' do
        it 'should include the module path' do
          error = nil

          begin
            subject.metasploit_class!(module_path, module_reference_name)
          rescue Msf::Modules::MetasploitClassCompatibilityError => error
          end

          expect(error).not_to be_nil
          expect(error.to_s).to include(module_path)
        end

        it 'should include the module reference name' do
          error = nil

          begin
            subject.metasploit_class!(module_path, module_reference_name)
          rescue Msf::Modules::MetasploitClassCompatibilityError => error
          end

          expect(error).not_to be_nil
          expect(error.to_s).to include(module_reference_name)
        end
      end
    end
  end

  context 'version_compatible!' do
    context 'without RequiredVersions' do
      it 'should not be defined' do
        expect(subject.const_defined?('RequiredVersions')).to be_falsey
      end

      it 'should not raise an error' do
        expect {
          subject.version_compatible!(module_path, module_reference_name)
        }.to_not raise_error
      end
    end

    context 'with RequiredVersions defined' do
      let(:minimum_api_version) do
        1
      end

      let(:minimum_core_version) do
        1
      end

      before(:example) do
        subject.const_set(
            :RequiredVersions,
            [
                minimum_core_version,
                minimum_api_version
            ]
        )
      end

      context 'with minimum Core version' do
        it 'is <= Metasploit::Framework::Core::GEM_VERSION when converted to Gem::Version' do
          expect(Gem::Version.new(minimum_core_version.to_s)).to be <= Metasploit::Framework::Core::GEM_VERSION
        end

        context 'without minimum API version' do
          let(:minimum_api_version) do
            2
          end

          it 'is > Metasploit::Framework::API::GEM_VERSION when converted to Gem::Version' do
            expect(Gem::Version.new(minimum_api_version.to_s)).to be > Metasploit::Framework::API::GEM_VERSION
          end

          it_should_behave_like 'Msf::Modules::VersionCompatibilityError'
        end

        context 'with minimum API version' do
          it 'should not raise an error' do
            expect {
              subject.version_compatible!(module_path, module_reference_name)
            }.to_not raise_error
          end
        end
      end

      context 'without minimum Core version' do
        let(:minimum_core_version) do
          5
        end

        it 'is > Metasploit::Framework::Core::GEM_VERSION when converted to Gem::Version' do
          expect(Gem::Version.new(minimum_core_version.to_s)).to be > Metasploit::Framework::Core::GEM_VERSION
        end

        context 'without minimum API version' do
          let(:minimum_api_version) do
            2
          end

          it 'is > Metasploit::Framework::API::GEM_VERSION when converted to Gem::Version' do
            expect(Gem::Version.new(minimum_api_version.to_s)).to be > Metasploit::Framework::API::GEM_VERSION
          end

          it_should_behave_like 'Msf::Modules::VersionCompatibilityError'
        end

        context 'with minimum API version' do
          it 'is <= Metasploit::Framework::API::GEM_VERSION when converted to Gem::Version' do
            expect(Gem::Version.new(minimum_api_version.to_s)).to be <= Metasploit::Framework::API::GEM_VERSION
          end

          it_should_behave_like 'Msf::Modules::VersionCompatibilityError'
        end
      end
    end
  end
end
