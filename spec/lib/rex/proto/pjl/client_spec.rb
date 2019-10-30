require 'spec_helper'
require 'msfenv'
require 'msf/base'
require 'rex/proto/pjl'

RSpec.describe Rex::Proto::PJL::Client do
  context "methods" do
    let(:default_response) do
      'OK'
    end

    let(:sock) do
      s = double("sock")
      allow(s).to receive(:put).with(an_instance_of(String))
      allow(s).to receive(:get).and_return(default_response)
      s
    end

    let(:cli) do
      Rex::Proto::PJL::Client.new(sock)
    end

    context "#initialize" do
      it "should initialize a 'sock' ivar" do
        expect(cli.instance_variable_get(:@sock).class).to eq(RSpec::Mocks::Double)
      end
    end

    context "#begin_job" do
      it "should send a PJL start request without an error" do
        expect { cli.begin_job }.to_not raise_error
      end
    end

    context "#end_job" do
      it "should send a PJL end request without an error" do
        expect { cli.end_job }.to_not raise_error
      end
    end

    context "#info" do
      it "should raise an exception for not having a category" do
        expect { cli.info(nil) }.to raise_error(ArgumentError)
      end

      it "should receive a response for an INFO request" do
        expect(cli.info(:id)).to eq(default_response)
      end
    end

    context "#info_id" do
      it "should return the version information" do
        fake_version = '"1337"'
        allow(cli).to receive(:info).with(an_instance_of(Symbol)).and_return(fake_version)
        expect(cli.info_id).to eq('1337')
      end
    end

    context "#info_variables" do
      it "should return the environment variables" do
        fake_env_vars = "#{Rex::Proto::PJL::Info::VARIABLES}\r\nPASSWORD=DISABLED\f"
        allow(cli).to receive(:info).with(an_instance_of(Symbol)).and_return(fake_env_vars)
        expect(cli.info_variables).to eq('PASSWORD=DISABLED')
      end
    end

    context "#info_filesys" do
      it "should return the volumes" do
        fake_volumes = "[1 TABLE]\r\nDIR\f"
        allow(cli).to receive(:info).with(an_instance_of(Symbol)).and_return(fake_volumes)
        expect(cli.info_filesys).to eq('DIR')
      end
    end

    context "#get_rdymsg" do
      it "should return a READY message" do
        fake_ready_message = 'DISPLAY="RES"'
        allow(cli).to receive(:info).with(an_instance_of(Symbol)).and_return(fake_ready_message)
        expect(cli.get_rdymsg).to eq('RES')
      end
    end

    context "#set_rdymsg" do
      it "should send a READY message without an error" do
        expect { cli.set_rdymsg("") }.to_not raise_error
      end
    end

    context "#fsinit" do
      it "should raise an exception due to an invalid volume" do
        expect { cli.fsinit("BAD") }.to raise_error(ArgumentError)
      end

      it "should send a FS INIT message without an error" do
        expect { cli.fsinit("1:") }.to_not raise_error
      end
    end

    context "#fsquery" do
      it "should raise an exception due to an invalid path" do
        expect { cli.fsquery("BAD") }.to raise_error(ArgumentError)
      end

      it "should query a file" do
        response = "TYPE=FILE SIZE=1337\r\n\f"
        tmp_sock = double("sock")
        allow(tmp_sock).to receive(:put).with(an_instance_of(String))
        allow(tmp_sock).to receive(:get).with(Rex::Proto::PJL::DEFAULT_TIMEOUT).and_return(response)
        tmp_cli = Rex::Proto::PJL::Client.new(tmp_sock)
        expect(tmp_cli.fsquery("1:")).to eq(true)
      end
    end

    context "#fsdirlist" do
      it "should reaise an exception due to an invalid path" do
        expect { cli.fsdirlist("BAD") }.to raise_error(ArgumentError)
      end

      it "should return a LIST directory response" do
        response = "ENTRY=1\r\nDIR\f"
        tmp_sock = double("sock")
        allow(tmp_sock).to receive(:put).with(an_instance_of(String))
        allow(tmp_sock).to receive(:get).with(Rex::Proto::PJL::DEFAULT_TIMEOUT).and_return(response)
        tmp_cli = Rex::Proto::PJL::Client.new(tmp_sock)
        expect(tmp_cli.fsdirlist("1:")).to eq('DIR')
      end
    end

    context "#fsupload" do
      it "should raise an exception due to an invalid path" do
        expect { cli.fsupload("BAD") }.to raise_error(ArgumentError)
      end

      it "should return a file" do
        response = "SIZE=1337\r\nFILE\f"
        tmp_sock = double("sock")
        allow(tmp_sock).to receive(:put).with(an_instance_of(String))
        allow(tmp_sock).to receive(:get).with(Rex::Proto::PJL::DEFAULT_TIMEOUT).and_return(response)
        tmp_cli = Rex::Proto::PJL::Client.new(tmp_sock)
        expect(tmp_cli.fsupload("1:")).to eq('FILE')
      end
    end

    context "#fsdownload" do
      it "should raise an exception due to an invalid path" do
        expect { cli.fsdownload("/dev/null", "BAD") }.to raise_error(ArgumentError)
      end

      it "should upload a file" do
        response = "TYPE=FILE SIZE=1337\r\n\f"
        tmp_sock = double("sock")
        allow(tmp_sock).to receive(:put).with(an_instance_of(String))
        allow(tmp_sock).to receive(:get).with(Rex::Proto::PJL::DEFAULT_TIMEOUT).and_return(response)
        tmp_cli = Rex::Proto::PJL::Client.new(tmp_sock)
        expect(tmp_cli.fsdownload("/dev/null", "1:")).to eq(true)
      end

      it "should upload data from a string" do
        response = "TYPE=FILE SIZE=1337\r\n\f"
        tmp_sock = double("sock")
        allow(tmp_sock).to receive(:put).with(an_instance_of(String))
        allow(tmp_sock).to receive(:get).with(Rex::Proto::PJL::DEFAULT_TIMEOUT).and_return(response)
        tmp_cli = Rex::Proto::PJL::Client.new(tmp_sock)
        expect(tmp_cli.fsdownload("Miscellaneous Data", "1:root/.workspace/.garbage.", is_file: false)).to eq(true)
      end
    end

    context "#fsdelete" do
      it "should raise an exception due to an invalid path" do
        expect { cli.fsdelete("BAD") }.to raise_error(ArgumentError)
      end

      it "should delete a file" do
        response = "FILEERROR=3\r\n\f"
        tmp_sock = double("sock")
        allow(tmp_sock).to receive(:put).with(an_instance_of(String))
        allow(tmp_sock).to receive(:get).with(Rex::Proto::PJL::DEFAULT_TIMEOUT).and_return(response)
        tmp_cli = Rex::Proto::PJL::Client.new(tmp_sock)
        expect(tmp_cli.fsdelete("1:")).to eq(true)
      end
    end
  end
end
