# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/framework'

RSpec.describe Msf::Framework do
  context '#initialize' do
    subject(:framework) {
      described_class.new
    }

    it 'creates no threads' do
      expect {
        framework
      }.not_to change { Thread.list.count }
    end
  end

  describe "#version" do
    subject(:framework) do
      described_class.new
    end

    it "should return the Version constant" do
      expect(described_class.const_get(:Version)).to eq framework.version
    end

    it "should return the concatenation of Major.Minor.Point-Release" do
      major,minor,point,release = framework.version.split(/[.-]/)
      expect(major.to_i).to eq described_class::Major
      expect(minor.to_i).to eq described_class::Minor
      expect(point.to_i).to eq described_class::Point
      expect("-#{release}").to eq described_class::Release
    end

    skip "conform to SemVer 2.0 syntax: http://semver.org/" do
      it "should have constants that correspond to SemVer standards" do
        major,minor,patch,label = framework.version.split(/[.-]/)
        expect(major.to_i).to eq described_class::VERSION::MAJOR
        expect(minor.to_i).to eq described_class::VERSION::MINOR
        expect(point.to_i).to eq described_class::VERSION::POINT
        expect(label.to_s).to eq described_class::VERSION::LABEL
      end
    end

  end

end
