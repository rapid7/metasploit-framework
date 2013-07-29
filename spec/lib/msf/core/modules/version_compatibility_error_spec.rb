# -*- coding:binary -*-
require 'spec_helper'

describe Msf::Modules::VersionCompatibilityError do
	it_should_behave_like 'Msf::Modules::Error subclass #initialize' do
		let(:minimum_api_version) do
			1
		end

		let(:minimum_core_version) do
			2
		end

		it 'should say cause was version check' do
			subject.to_s.should match(/due to version check/)
		end

		context 'with :minimum_api_version' do
			subject do
				described_class.new(
						:minimum_api_version => minimum_api_version
				)
			end

			it 'should set minimum_api_version' do
				subject.minimum_api_version.should == minimum_api_version
			end

			it 'should include minimum_api_version in error' do
				subject.to_s.should match(/due to version check \(requires API >= #{minimum_api_version}\)/)
			end
		end

		context 'with :minimum_api_version and :minimum_core_version' do
			subject do
				described_class.new(
						:minimum_api_version => minimum_api_version,
				    :minimum_core_version => minimum_core_version
				)
			end

			it 'should include minimum_api_version and minimum_core_version in error' do
				subject.to_s.should match(/due to version check \(requires API >= #{minimum_api_version} and Core >= #{minimum_core_version}\)/)
			end
		end

		context 'with :minimum_core_version' do
			subject do
				described_class.new(
						:minimum_core_version => minimum_core_version
				)
			end

			it 'should set minimum_core_version' do
				subject.minimum_core_version.should == minimum_core_version
			end

			it 'should include minimum_core_version in error' do
				subject.to_s.should match(/due to version check \(requires Core >= #{minimum_core_version}\)/)
			end
		end
	end
end
