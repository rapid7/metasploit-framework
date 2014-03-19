# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/framework'

describe Msf::Framework do
  include_context 'Msf::Framework'

  subject do
    framework
  end

  context 'CONSTANTS' do
    context 'Version' do
      subject(:version) do
        described_class::Version
      end

      it { should == '4.9.0-dev' }

      it "should return the concatenation of Major.Minor.Point-Release" do
        major,minor,point,release = version.split(/[.-]/)
        major.to_i.should == described_class::Major
        minor.to_i.should == described_class::Minor
        point.to_i.should == described_class::Point
        "-#{release}".should == described_class::Release
      end

      pending "conform to SemVer 2.0 syntax: http://semver.org/" do
        it "should have constants that correspond to SemVer standards" do
          major,minor,patch,label = subject.version.split(/[.-]/)
          major.to_i.should == described_class::VERSION::MAJOR
          minor.to_i.should == described_class::VERSION::MINOR
          point.to_i.should == described_class::VERSION::POINT
          label.to_s.should == described_class::VERSION::LABEL
        end
      end
    end
  end

  describe "#version" do
    subject(:version) do
      framework.version
    end

    it "should return the Version constant" do
      expect(version).to eq(described_class::Version)
    end
  end
end
