# -*- encoding: utf-8 -*-
require 'rack'

describe Rack do
  describe 'version' do
    it 'defaults to a hard-coded api version' do
      Rack.version.should.equal("1.3")
    end
  end
  describe 'release' do
    it 'matches version in .gemspec' do
      gemspec_path = File.join(File.dirname(File.expand_path(__FILE__)), '../rack.gemspec')
      gemspec = Gem::Specification.load(gemspec_path)
      Rack.release.split('.').take(2).should.equal gemspec.version.to_s.split('.').take(2)
    end
  end
end
