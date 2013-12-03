require 'spec_helper'

require 'bundler'

describe Bundler do

  context '#bundle_path' do

    subject(:bundle_path) do
      described_class.bundle_path.realpath
    end

    before(:all) do
      root_dir = Metasploit::Framework.root
    end

    it { should be_directory }

    it { should be_writable }

    it.to_s { should include 'vendor/bundle' }

    it.to_s { should_not include '..' }

  end

end
