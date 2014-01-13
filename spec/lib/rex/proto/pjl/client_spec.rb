require 'spec_helper'
require 'fastlib'
require 'msfenv'
require 'msf/base'
require 'rex/proto/pjl'

describe Rex::Proto::PJL::Client do
  context "methods" do
    let(:default_response) do
      'OK'
    end

    let(:sock) do
      s = double("sock")
      s.stub(:put).with(an_instance_of(String))
      s.stub(:get).and_return(default_response)
      s
    end

    let(:cli) do
      Rex::Proto::PJL::Client.new(sock)
    end

    context ".initialize" do
      it "should initialize a 'sock' ivar" do
        cli.instance_variable_get(:@sock).class.should eq(RSpec::Mocks::Mock)
      end
    end

    context ".begin_job" do
      it "should send a PJL start request without any errors" do
        cli.begin_job
      end
    end

    context ".end_job" do
      it "should send a PJL end request" do
        cli.end_job
      end
    end

    context ".info" do
      it "should raise an exception for not having a category" do
        expect { cli.info(nil) }.to raise_error(ArgumentError)
      end

      it "should receive a response for an INFO request" do				
        cli.info(:id).should eq(default_response)
      end
    end

    context ".info_id" do
      it "should return the version information" do
        fake_version = '"1337"'
        cli.stub(:info).with(an_instance_of(Symbol)).and_return(fake_version)
        cli.info_id.should eq('1337')
      end
    end

    context ".info_filesys" do
      it "should return the volumes" do
        fake_volumes = "[1 TABLE]\r\nDIR\f"
        cli.stub(:info).with(an_instance_of(Symbol)).and_return(fake_volumes)
        cli.info_filesys.should eq('DIR')
      end
    end

    context ".get_rdymsg" do
      it "should return a READY message" do
        fake_ready_message = 'DISPLAY="RES"'
        cli.stub(:info).with(an_instance_of(Symbol)).and_return(fake_ready_message)
        cli.get_rdymsg.should eq('RES')
      end
    end

    context ".set_rdymsg" do
      it "should send a READY message" do
        cli.set_rdymsg("")
      end
    end

    context ".fsinit" do
      it "should raise an exception due to an invalid volume" do
        expect { cli.fsinit("BAD") }.to raise_error(ArgumentError)
      end

      it "should send a FS INIT message" do
        cli.fsinit("1:")
      end
    end

    context ".fsdirlist" do
      it "should reaise an exception due to an invaid path name" do
        expect { cli.fsdirlist("BAD") }.to raise_error(ArgumentError)
      end

      it "should return a LIST directory response" do
        cli.fsinit("1:")
      end
    end

    context ".fsupload" do
      it "should raise an exception due to an invalid path name" do
        expect { cli.fsupload("BAD") }.to raise_error(ArgumentError)
      end

      it "should return a file" do
        size_response = "SIZE=1337\r\nFILE\f"
        tmp_sock = double("sock")
        tmp_sock.stub(:put).with(an_instance_of(String))
        tmp_sock.stub(:get).with.and_return(size_response)
        tmp_cli = Rex::Proto::PJL::Client.new(tmp_sock)
        tmp_cli.fsupload("1:").should eq('FILE')
      end
    end
  end
end