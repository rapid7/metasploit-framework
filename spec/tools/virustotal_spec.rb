require 'spec_helper'

load Metasploit::Framework.root.join('tools/exploit/virustotal.rb').to_path

require 'msfenv'
require 'msf/base'
require 'digest/sha2'

RSpec.describe VirusTotalUtility do

  context "Classes" do
    let(:api_key) do
      'FAKE_API_KEY'
    end

    let(:filename) do
      'MALWARE.EXE'
    end

    let(:malware_data) do
      'DATA'
    end

    describe VirusTotalUtility::ToolConfig do
      context "Class methods" do

        let(:tool_config) do
          VirusTotalUtility::ToolConfig.new
        end

        context ".Initializer" do
          it "should init the config file path as Metasploit's default config path" do
            expect(tool_config.instance_variable_get(:@config_file)).to eq(Msf::Config.config_file)
          end

          it "should init the group name as 'VirusTotal'" do
            expect(tool_config.instance_variable_get(:@group_name)).to eq('VirusTotal')
          end
        end
      end
    end

    describe VirusTotalUtility::VirusTotal do
      context "Class methods" do

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
          allow(File).to receive(:open).with(filename, 'rb') {|&block| block.yield file}
          VirusTotalUtility::VirusTotal.new({'api_key'=>api_key, 'sample'=>filename})
        end

        context ".Initializer" do
          it "should have an API key" do
            expect(vt.instance_variable_get(:@api_key)).to eq(api_key)
          end

          it "should have a checksum for the malware sample" do
            expect(vt.instance_variable_get(:@sample_info)['sha256']).to eq(malware_sha256)
          end
        end

        context "._load_sample" do
          it "should contain sample info including data, filename, and sha256" do
            expect(vt.send(:_load_sample, filename)).to eq(sample)
          end
        end

        context ".scan_sample" do
          it "should return with data" do
            expect(vt).to receive(:_execute_request).and_return('')
            expect(vt.scan_sample).to eq('')
          end
        end

        context ".retrieve_report" do
          it "should return with data" do
            expect(vt).to receive(:_execute_request).and_return('')
            expect(vt.retrieve_report).to eq('')
          end
        end

        context "._execute_request" do
          it "should return status code 204" do
            res = double(Rex::Proto::Http::Response)
            expect(res).to receive(:code).and_return(204)
            expect(vt).to receive(:send_request_cgi).with(scan_sample_opts).and_return(res)
            expect { vt.send(:_execute_request, scan_sample_opts) }.to raise_error(RuntimeError)
          end

          it "should return status code 403" do
            res = double(Rex::Proto::Http::Response)
            expect(res).to receive(:code).and_return(403)
            expect(vt).to receive(:send_request_cgi).with(scan_sample_opts).and_return(res)
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

          before(:example) do
            @upload_data = vt.send(:_create_upload_data, form_opts)
          end

          it "should create form-data with a boundary" do
            expect(@upload_data).to match(/#{boundary}/)
          end

          it "should create form-data with the API key" do
            expect(@upload_data).to match(/#{api_key}/)
          end

          it "should create form-data with the malware filename" do
            expect(@upload_data).to match(/#{filename}/)
          end

          it "should create form-data with the malware data" do
            expect(@upload_data).to match(/#{malware_data}/)
          end
        end
      end
    end


    describe VirusTotalUtility::Driver do
      before do
        $stdin = StringIO.new("Y\n")
      end

      after do
        $stdin = STDIN
      end

      let(:driver) do
        argv = "-k #{api_key} -f #{filename}".split
        options = {
          'samples' => filename,
          'api_key' => api_key,
          'delay'   => 60
        }

        expect(VirusTotalUtility::OptsConsole).to receive(:parse).with(anything).and_return(options)

        tool_config = instance_double(
          VirusTotalUtility::ToolConfig,
          has_privacy_waiver?: true,
          load_api_key: api_key,
          save_api_key: nil,
          save_privacy_waiver: nil
        )

        expect(VirusTotalUtility::ToolConfig).to receive(:new).and_return(tool_config)

        d = nil

        get_stdout {
          d = VirusTotalUtility::Driver.new
        }

        d
      end

      context ".Class methods" do

        context ".initialize" do
          it "should return a Driver object" do
            expect(driver.class).to eq(VirusTotalUtility::Driver)
          end
        end

        context ".ask_privacy" do
          it "should have a link of VirusTotal's terms of service" do
            tos = 'https://www.virustotal.com/en/about/terms-of-service'
            out = get_stdout { driver.ack_privacy }
            expect(out).to match(/#{tos}/)
          end
        end

        context ".generate_report" do
          it "should show a report" do
            res = {
              "scans" => {
                "Bkav" => { "detected" => false, "version" => "1.3.0.4613", "result" => nil, "update" => "20140107" }
              },
              "response_code" => 1
            }

            out = get_stdout { driver.generate_report(res, filename) }
            expect(out).to match(/#{res['scans']['Bkav']['version']}/)
          end
        end
      end
    end
  end
end
