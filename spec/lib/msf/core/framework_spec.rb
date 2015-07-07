# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/framework'

describe Msf::Framework do
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
    CURRENT_VERSION = "4.11.3-dev"

    subject(:framework) do
      described_class.new
    end

    it "should return the current version" do
      framework.version.should == CURRENT_VERSION
    end

    it "should return the Version constant" do
      described_class.const_get(:Version).should == framework.version
    end

    it "should return the concatenation of Major.Minor.Point-Release" do
      major,minor,point,release = framework.version.split(/[.-]/)
      major.to_i.should == described_class::Major
      minor.to_i.should == described_class::Minor
      point.to_i.should == described_class::Point
      "-#{release}".should == described_class::Release
    end

    skip "conform to SemVer 2.0 syntax: http://semver.org/" do
      it "should have constants that correspond to SemVer standards" do
        major,minor,patch,label = framework.version.split(/[.-]/)
        major.to_i.should == described_class::VERSION::MAJOR
        minor.to_i.should == described_class::VERSION::MINOR
        point.to_i.should == described_class::VERSION::POINT
        label.to_s.should == described_class::VERSION::LABEL
      end
    end

  end

end
