require 'spec_helper'
require 'rex/proto/http/request'

describe Rex::Proto::Http::Request do

  let(:resource)    { '/test.php' }
  let(:method)      { 'GET' }
  let(:qstring)     { '?id=1' }
  let(:get_request) { "#{method} #{resource}#{qstring} HTTP/1.1" }

  context Rex::Proto::Http::Request::Get do
    it "should initialize" do
      Rex::Proto::Http::Request::Get.new
    end
  end

  context Rex::Proto::Http::Request::Post do
    it "should initialize" do
      Rex::Proto::Http::Request::Post.new
    end
  end

  context Rex::Proto::Http::Request::Put do
    it "should initialize" do
      Rex::Proto::Http::Request::Put.new
    end
  end

  context "Class Request" do
    subject(:cli) { Rex::Proto::Http::Request.new(method, resource) }

    context "Methods" do
      context ".update_cmd_parts" do
        it "should update uri parts" do
          cli.update_cmd_parts(get_request).should eq(resource)
        end

        it "should raise a RuntimeError due to an invalid request command string" do
          expect { cli.update_cmd_parts("") }.to raise_error(RuntimeError)
        end
      end

      context ".update_uri_parts" do
        it "should get the parts from a query string" do
          cli.raw_uri = get_request
          cli.update_uri_parts.should eq("#{method} #{resource}")
        end

        it "should set the URI the same as the resource being requested" do
          cli.raw_uri = ''
          cli.update_uri_parts.should be_empty
        end
      end

      context ".normalize!" do
        it "should remove a double slash in the URI" do
          cli.normalize!(qstring).should eq(0)
        end
      end

      context ".uri" do
        subject { cli.uri_parts['Resource'] = resource }
        it "should return an uri with junk_self_referring_directories" do
          cli.stub(:junk_self_referring_directories).and_return(true)
          cli.uri.should match(/[\.\/]+#{resource}/)
        end

        it "should return an uri with junk_param_start" do
          cli.stub(:junk_param_start).and_return(true)
          cli.uri.should match(/\/%3f.+#{resource}$/)
        end

        it "should return an uri with junk_directories" do
          cli.stub(:junk_directories).and_return(true)
          cli.uri.should match(/.+#{resource}/)
        end

        it "should return an uri with junk_slashes" do
          cli.stub(:junk_slashes).and_return(true)
          cli.uri_parts['Resource'] = "/#{resource}"
          cli.uri.should eq(resource)
        end

        it "should return an uri with junk_end_of_uri" do
          cli.stub(:junk_end_of_uri).and_return(true)
          cli.uri.should eq("/%20HTTP/1.0%0d%0a/../..#{resource}")
        end

      end

      context ".param_string" do
        it "should return params with junk_params" do
          cli.uri_parts['QueryString'] = {'param' => ['1'] }
          cli.stub(:junk_params).and_return(true)
          cli.param_string.should match(/.+=.+/)
        end

        it "should return params with with a value" do
          cli.uri_parts['QueryString'] = {'param' => '1' }
          cli.param_string.should eq('param=1')
        end

        it "should return a param with out a value" do
          cli.uri_parts['QueryString'] = {'param' => nil }
          cli.param_string.should eq('param')
        end

      end

      context ".uri=" do
        it "should update the underlying URI structure" do
          uri = cli.uri=(resource)
          uri.should eq(resource)
        end
      end

      context ".to_s" do
        it "should return a request packet with junk_pipeline" do
          cli.stub(:junk_pipeline).and_return(1)
          cli.headers['Host'] = 'Host'
          cli.to_s.should match(resource)
        end
      end

      context ".body" do
        it "should return a body" do
          cli.body.should eq('')
        end

        it "should return a param_string" do
          cli.stub(:method).and_return('POST')
          cli.body.should eq('')
        end
      end

      context ".cmd_string" do
        it "should return the command string" do
          cli.cmd_string.should match(/#{resource}/)
        end
      end

      context ".resource" do
        it "should return a resource" do
          cli.resource.should match(/#{resource}/)
        end
      end

      context ".resource=" do
        it "should return an user-specified resource" do
          tmp_resource = '/test_resource.php'
          cli.resource=(tmp_resource).should eq(tmp_resource)
        end
      end

      context ".qstring" do
        it "should return a query string" do
          test_string = 'test'
          cli.uri_parts['QueryString'] = test_string
          cli.qstring.should eq(test_string)
        end
      end

      context ".parse_cgi_qstring" do
        it "should parse and return a CGI qstring" do
          qstring_opts = {
            'id'       => '1',
            'username' => 'user'
          }

          tmp = []
          qstring_opts.each_pair { |k, v| tmp << "#{k}=#{v}" }
          qstring = tmp * "&"
          cli.parse_cgi_qstring(qstring).should eq(qstring_opts)
        end
      end
    end
  end

end