require 'spec_helper'

require 'bundler'

describe Bundler do

  context '#bundle_path' do
    subject(:bundle_path) do
      described_class.bundle_path.realpath
    end

    let(:root_dir) do
      Metasploit::Framework.root
    end

    it { should be_directory }

    it { should be_writable }

    it 'should be local' do
      bundle_path.relative_path_from(root_dir).to_s.should_not include '..'
    end

    context '#to_s' do
      subject(:to_s) do
        bundle_path.to_s
      end

      it { should include 'vendor/bundle' }

    end
  end
end
