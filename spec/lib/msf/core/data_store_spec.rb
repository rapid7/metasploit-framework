# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/data_store'

shared_examples "datastore" do
	it "should have options" do
		subject["foo"].should == "bar"
		subject["fizz"].should == "buzz"
	end
	it "should have case-insensitive keys" do
		# Sorted by gray code, just for fun
		subject["foo"].should == "bar"
		subject["Foo"].should == "bar"
		subject["FOo"].should == "bar"
		subject["fOo"].should == "bar"
		subject["fOO"].should == "bar"
		subject["FOO"].should == "bar"
		subject["FoO"].should == "bar"
		subject["foO"].should == "bar"
	end
	context "#to_h" do
		it "should return a Hash with correct values" do
			subject.to_h.should == { "foo" => "bar", "fizz" => "buzz" }
		end
	end
end

describe Msf::DataStore do

	describe "#import_option" do
		subject do
			s = described_class.new
			s.import_option("foo", "bar")
			s.import_option("fizz", "buzz")
			s
		end
		it_behaves_like "datastore"
	end

	describe "#import_options_from_hash" do
		subject do
			hash = { "foo" => "bar", "fizz" => "buzz" }
			s = described_class.new
			s.import_options_from_hash(hash)
			s
		end
		it_behaves_like "datastore"
	end

	describe "#import_options_from_s" do
		subject do
			str = "foo=bar fizz=buzz"
			s = described_class.new
			s.import_options_from_s(str)
			s
		end
		it_behaves_like "datastore"
	end

	describe "#from_file" do
		subject do
			ini_instance = double
			ini_instance.stub(:group?).and_return(true)
			ini_instance.stub(:[]).and_return( { "foo" => "bar", "fizz" => "buzz" } )

			ini = stub_const("Rex::Parser::Ini", Class.new)
			ini.stub(:from_file).and_return(ini_instance)

			s = described_class.new
			s.from_file("path")
			s
		end

		it_behaves_like "datastore"
	end


end
