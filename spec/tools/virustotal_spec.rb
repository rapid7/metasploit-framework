require 'spec_helper'

load Metasploit::Framework.root.join('tools/virustotal.rb').to_path

require 'fastlib'
require 'msfenv'
require 'msf/base'
require 'digest/sha2'

describe ToolConfig do
  context "Class methods" do

    let(:tool_config) do
      ToolConfig.new
    end

    context ".Initializer" do
      it "should init the config file path as Metasploit's default config path" do
        tool_config.instance_variable_get(:@config_file).should eq(Msf::Config.config_file)
      end

      it "should init the group name as 'VirusTotal'" do
        tool_config.instance_variable_get(:@group_name).should eq('VirusTotal')
      end
    end

  end
end

describe VirusTotal do
  context "Class methods" do

    let(:api_key) do
      'FAKE_API_KEY'
    end

    let(:filename) do
      'MALWARE.EXE'
    end

    let(:malware_data) do
      'DATA'
    end

    let(:malware_sha256) do
      Digest::SHA256.hexdigest(malware_data)
    end

    let(:sample) do
      {
        'filename' => filename,
        'data'     => malware_data,
        'sha256'   => malware_sha256
      }
    end

    let(:boundary) do
      'THEREAREMANYLIKEITBUTTHISISMYDATA'
    end

    let(:scan_sample_opts) do
      opts = {
        'boundary' => boundary,
        'api_key'  => api_key,
        'filename' => filename,
        'data'     => malware_data
      }

      return opts
    end

    let(:retrieve_report_opts) do
      opts = {
        'uri'       => '/vtapi/v2/file/report',
        'method'    => 'POST',
        'vhost'     => 'www.virustotal.com',
        'vars_post' => {
          'apikey'   => api_key,
          'resource' => malware_sha256
        }
      }

      return opts
    end

    let(:vt) do
      file = double(File, read: malware_data)
      File.stub(:open).with(filename, 'rb') {|&block| block.yield file}
      VirusTotal.new({'api_key'=>api_key, 'sample'=>filename})
    end

    context ".Initializer" do
      it "should have an API key" do
        vt.instance_variable_get(:@api_key).should eq(api_key)
      end

      it "should have a checksum for the malware sample" do
        vt.instance_variable_get(:@sample_info)['sha256'].should eq(malware_sha256)
      end
    end

    context "._load_sample" do
      it "should contain sample info including data, filename, and sha256" do
        vt.send(:_load_sample, filename).should eq(sample)
      end
    end

    context ".scan_sample" do
      it "should return with data" do
        vt.stub(:_execute_request).and_return('')
        vt.scan_sample.should eq('')
      end
    end

    context ".retrieve_report" do
      it "should return with data" do
        vt.stub(:_execute_request).and_return('')
        vt.retrieve_report.should eq('')
      end
    end

    context "._execute_request" do
      it "should return status code 204" do
        res = double(Rex::Proto::Http::Response)
        res.stub(:code).and_return(204)
        vt.stub(:send_request_cgi).with(scan_sample_opts).and_return(res)
        expect { vt.send(:_execute_request, scan_sample_opts) }.to raise_error(RuntimeError)
      end

      it "should return status code 403" do
        res = double(Rex::Proto::Http::Response)
        res.stub(:code).and_return(403)
        vt.stub(:send_request_cgi).with(scan_sample_opts).and_return(res)
        expect { vt.send(:_execute_request, scan_sample_opts) }.to raise_error(RuntimeError)
      end
    end

    context "._create_upload_data" do

      let(:form_opts) do
        {
          'boundary' => boundary,
          'api_key'  => api_key,
          'filename' => filename,
          'data'     => malware_data
        }
      end

      before(:each) do
        @upload_data = vt.send(:_create_upload_data, form_opts)
      end

      it "should create form-data with a boundary" do
        @upload_data.should match(/#{boundary}/)
      end

      it "should create form-data with the API key" do
        @upload_data.should match(/#{api_key}/)
      end

      it "should create form-data with the malware filename" do
        @upload_data.should match(/#{filename}/)
      end

      it "should create form-data with the malware data" do
        @upload_data.should match(/#{malware_data}/)
      end
    end
  end


  describe Driver do
    # Get stdout:
    # http://stackoverflow.com/questions/11349270/test-output-to-command-line-with-rspec
    def get_stdout(&block)
      out = $stdout
      $stdout = fake = StringIO.new
      begin
        yield
      ensure
        $stdout = out
      end
      fake.string
    end

    before do
      $stdin = StringIO.new("Y\n")
    end

    after do
      $stdin = STDIN
    end

    let(:filename) do
      'MALWARE.EXE'
    end

    let(:api_key) do
      'KEY'
    end

    let(:driver) do
      argv = "-k #{api_key} -f #{filename}".split
      options = {
        'samples' => filename,
        'api_key' => api_key,
        'delay'   => 60
      }

      OptsConsole.stub(:parse).with(anything).and_return(options)

      tool_config = double(ToolConfig)
      tool_config.stub(:config_has_privacy_waiver?).and_return(true)
      tool_config.stub(:load_api_key).and_return(api_key)

      d = nil

      out = get_stdout {
        d = Driver.new
      }

      d
    end

    context ".Class methods" do
      context ".initialize" do
        it "should return a Driver object" do
          driver.class.should eq(Driver)
        end
      end

      context ".ask_privacy" do
        it "should have a link of VirusTotal's terms of service" do
          tos = 'https://www.virustotal.com/en/about/terms-of-service/'
          #puts driver.class.inspect
          #puts driver.methods.inspect
          #puts driver.inspect
        end
      end

      context ".generate_report" do
      end
    end
  end

end