# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/framework'

describe Msf::Framework do

  describe "#version" do
    CURRENT_VERSION = "4.9.0-dev"

    subject do
      described_class.new
    end

    it "should return the current version" do
      subject.version.should == CURRENT_VERSION
    end

    it "should return the Version constant" do
      described_class.const_get(:Version).should == subject.version
    end

    it "should return the concatenation of Major.Minor.Point-Release" do
      major,minor,point_release = CURRENT_VERSION.split(".")
      point,release = point_release.split("-")
      major.to_i.should == described_class.const_get(:Major)
      minor.to_i.should == described_class.const_get(:Minor)
      point.to_i.should == described_class.const_get(:Point)
      "-#{release}".should == described_class.const_get(:Release)
    end

  end

end
