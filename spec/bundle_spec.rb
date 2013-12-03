require 'spec_helper'
require 'bundler'



describe Bundler do
  context '#bundle_path' do

    path = described_class.bundle_path.realpath
    root_dir = Metasploit::Framework.root #.to_s

    it 'should point to a directory' do
      path.should be_directory
    end

    it 'should point to a vendor/bundle directory' do
      path.to_s.should =~ /vendor\/bundle/
    end

    it 'should be local to the installation' do
      path.relative_path_from(root_dir).to_s.should_not =~ /\.\./
    end

    it 'should point to a writable directory' do
      path.should be_writable
    end

  end
end
