# -*- coding:binary -*-

RSpec.describe Rex::Proto::Http::HttpLoggerSubscriber do
  include_context 'Msf::UIDriver'
  let(:mock_module) {instance_double Msf::Exploit}

  subject do
    capture_logging(mock_module)
    Rex::Proto::Http::HttpLoggerSubscriber.new(logger: mock_module)
  end

  let(:response) { Rex::Proto::Http::Response.new(200, 'OK') }

  before(:example) do
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:request_cgi).with(any_args)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv).with(any_args).and_return(response)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:set_config).with(any_args)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:close)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect)
  end
 
  describe '#on_request' do
    let(:sample_request) do
      req = Rex::Proto::Http::ClientRequest.new({
        'agent' => 'Met',
        'data' => 'bufaction=verifyLogin&user=admin&password=turnkey'
      })
      req
    end

    let(:normal_request_output) do
      [
        '####################',
        '# Request:',
        '####################',
        "%clr%bld%redGET / HTTP/1.1\r",
        "Host: \r",
        "User-Agent: Met\r",
        "Content-Length: 49\r",
        "\r",
        'bufaction=verifyLogin&user=admin&password=turnkey%clr'
      ]
    end

    let(:headers_only_request_output) do
      [
        '####################',
        '# Request:',
        '####################',
        "%clr%bld%redGET / HTTP/1.1\r",
        "Host: \r",
        "User-Agent: Met\r",
        "Content-Length: 49\r",
        '%clr'
      ]
    end
    
    let(:http_trace_colors_request_output) do
      [
        '####################',
        '# Request:',
        '####################',
        "%clr%bld%bluGET / HTTP/1.1\r",
        "Host: \r",
        "User-Agent: Met\r",
        "Content-Length: 49\r",
        "\r",
        'bufaction=verifyLogin&user=admin&password=turnkey%clr'
      ]
    end
    
    let(:http_trace_single_color_request_output) do
      [
        '####################',
        '# Request:',
        '####################',
        "%clr%bld%yelGET / HTTP/1.1\r",
        "Host: \r",
        "User-Agent: Met\r",
        "Content-Length: 49\r",
        "\r",
        'bufaction=verifyLogin&user=admin&password=turnkey%clr'
      ]
    end
    
    let(:http_trace_single_color_request_output_leading_slash) do
      [
        '####################',
        '# Request:',
        '####################',
        "%clrGET / HTTP/1.1\r",
        "Host: \r",
        "User-Agent: Met\r",
        "Content-Length: 49\r",
        "\r",
        'bufaction=verifyLogin&user=admin&password=turnkey%clr'
      ]
    end
    
    let(:http_trace_no_color_request_output) do
      [
        '####################',
        '# Request:',
        '####################',
        "%clrGET / HTTP/1.1\r",
        "Host: \r",
        "User-Agent: Met\r",
        "Content-Length: 49\r",
        "\r",
        'bufaction=verifyLogin&user=admin&password=turnkey%clr'
      ]
    end

    let(:mock_module) { instance_double Msf::Exploit, datastore: mock_datastore } 

    context 'when HttpTrace is set' do
      let(:mock_datastore) do {
        'HttpTrace' => true
      }
      end

      it 'should output the provided request with headers when HttpTrace is set' do
        subject.on_request(sample_request)
        expect(@output).to eq normal_request_output
      end
    end

    context 'when HttpTraceHeadersOnly is set' do
      let(:mock_datastore) do {
        'HttpTrace' => true,
        'HttpTraceHeadersOnly' => true
      }
      end

      it 'should log HTTP request with headers only when HttpTraceHeadersOnly is set' do
        subject.on_request(sample_request)
        expect(@output).to eq headers_only_request_output
      end
    end

    context 'when HttpTraceHeadersOnly is unset' do
      let(:mock_datastore) do {
        'HttpTrace' => true,
        'HttpTraceHeadersOnly' => nil
      }
      end

      it 'should log HTTP request with body when HttpTraceHeadersOnly is unset' do
        subject.on_request(sample_request)
        expect(@output).to eq normal_request_output
      end
    end

    context 'when HttpTraceColors is set' do
      let(:mock_datastore) do {
        'HttpTrace' => true,
        'HttpTraceColors' => 'blu/grn'
      }
      end

      it 'should log HTTP request in the respective color specified' do
        subject.on_request(sample_request)
        expect(@output).to eq http_trace_colors_request_output
      end
    end

    context 'when HttpTraceColors is set to a single color' do
      let(:mock_datastore) do {
        'HttpTrace' => true,
        'HttpTraceColors' => 'yel/'
      }
      end

      it 'should only log HTTP request in color when only one color is specified followed by a trailing "/"' do
        subject.on_request(sample_request)
        expect(@output).to eq http_trace_single_color_request_output
      end
    end 

    context 'when HttpTraceColors is set to a single color after a leading "/"' do
      let(:mock_datastore) do {
        'HttpTrace' => true,
        'HttpTraceColors' => '/yel'
      }
      end

      it 'should only log HTTP request in no color' do
        subject.on_request(sample_request)
        expect(@output).to eq http_trace_single_color_request_output_leading_slash
      end
    end

    context 'when HttpTraceColors is set to "/"' do
      let(:mock_datastore) do {
        'HttpTrace' => true,
        'HttpTraceColors' => '/'
      }
      end

      it 'should not log HTTP request in color' do
        subject.on_request(sample_request)
        expect(@output).to eq http_trace_no_color_request_output
      end
    end

    context 'when HttpTraceColors is set to only one color without "/"' do
      let(:mock_datastore) do {
        'HttpTrace' => true,
        'HttpTraceColors' => 'yel'
      }
      end

      it 'should only log HTTP request in color when only one color is specified without any "/"s' do
        subject.on_request(sample_request)
        expect(@output).to eq http_trace_single_color_request_output
      end
    end

    context 'when HttpTraceColors is set to false' do
      let(:mock_datastore) do {
        'HttpTrace' => false
      }
      end

      it 'should not log HTTP request' do
        subject.on_request(sample_request)
        expect(@output).to eq nil
      end
    end

    context 'when HttpTraceColors is unset' do
      let(:mock_datastore) do {
        'HttpTrace' => nil
      }
      end

      it 'should not log HTTP request' do
        subject.on_request(sample_request)
        expect(@output).to eq nil
      end
    end

  end

  describe '#on_response' do
    let(:sample_response) do
      res = Rex::Proto::Http::Response.new(302, 'Found')
      allow(res).to receive(:body).and_return('Location: https://www.google.com/?gws_rd=ssl')
      res
    end

    
    let(:normal_response_output) do
      [
        '####################',
        '# Response:',
        '####################',
        "%clr%bld%bluHTTP/1.1 302 Found\r",
        "\r",
        'Location: https://www.google.com/?gws_rd=ssl%clr'
      ]
    end

    let(:nil_response_output) do
      [
        '####################',
        '# Response:',
        '####################',
        'No response received'
      ]
    end

    
    let(:headers_only_response_output) do
      [
        '####################',
        '# Response:',
        '####################',
        "%clr%bld%bluHTTP/1.1 302 Found\r",
        "\r",
        '%clr'
      ]
    end

    
    let(:http_trace_colors_response_output) do
      [
        '####################',
        '# Response:',
        '####################',
        "%clr%bld%grnHTTP/1.1 302 Found\r",
        "\r",
        'Location: https://www.google.com/?gws_rd=ssl%clr'
      ]
    end

    
    let(:http_trace_single_color_response_output) do
      [
        '####################',
        '# Response:',
        '####################',
        "%clrHTTP/1.1 302 Found\r",
        "\r",
        'Location: https://www.google.com/?gws_rd=ssl%clr'
      ]
    end

    
    let(:http_trace_single_color_response_output_leading_slash) do
      [
        '####################',
        '# Response:',
        '####################',
        "%clr%bld%yelHTTP/1.1 302 Found\r",
        "\r",
        'Location: https://www.google.com/?gws_rd=ssl%clr'
      ]
    end

    
    let(:http_trace_no_color_response_output) do
      [
        '####################',
        '# Response:',
        '####################',
        "%clrHTTP/1.1 302 Found\r",
        "\r",
        'Location: https://www.google.com/?gws_rd=ssl%clr'
      ]
    end

    let(:mock_module) { instance_double Msf::Exploit, datastore: mock_datastore } 

    context 'when HttpTrace is set' do
      let(:mock_datastore) do {
        'HttpTrace' => true
      }
      end

      it 'should output the provided response with headers when HttpTrace is set' do
        subject.on_response(sample_response)
        expect(@output).to eq normal_response_output
      end

      it 'should give "no response received" message for nil response' do
        subject.on_response(nil)
        expect(@output).to eq nil_response_output
      end
    end

    context 'when HttpTraceHeadersOnly is set' do
      let(:mock_datastore) do {
        'HttpTrace' => true,
        'HttpTraceHeadersOnly' => true
      }
      end

      it 'should log HTTP response with headers only when HttpTraceHeadersOnly is set' do
        subject.on_response(sample_response)
        expect(@output).to eq headers_only_response_output
      end
    end

    context 'when HttpTraceHeadersOnly is unset' do
      let(:mock_datastore) do {
        'HttpTrace' => true,
        'HttpTraceHeadersOnly' => nil
      }
      end

      it 'should log HTTP response with body when HttpTraceHeadersOnly is unset' do
        subject.on_response(sample_response)
        expect(@output).to eq normal_response_output
      end
    end

    context 'when HttpTraceColors is set' do
      let(:mock_datastore) do {
        'HttpTrace' => true,
        'HttpTraceColors' => 'blu/grn'
      }
      end

      it 'should log HTTP response in the respective color specified' do
        subject.on_response(sample_response)
        expect(@output).to eq http_trace_colors_response_output
      end
    end

    context 'when HttpTraceColors is set to a single color' do
      let(:mock_datastore) do {
        'HttpTrace' => true,
        'HttpTraceColors' => 'yel/'
      }
      end

      it 'should log HTTP response in no color' do
        subject.on_response(sample_response)
        expect(@output).to eq http_trace_single_color_response_output
      end
    end 

    context 'when HttpTraceColors is set to a single color after a leading "/"' do
      let(:mock_datastore) do {
        'HttpTrace' => true,
        'HttpTraceColors' => '/yel'
      }
      end

      it 'should log HTTP response in color when only one color is specified after a leading "/"' do
        subject.on_response(sample_response)
        expect(@output).to eq http_trace_single_color_response_output_leading_slash
      end
    end

    context 'when HttpTraceColors is set to "/"' do
      let(:mock_datastore) do {
        'HttpTrace' => true,
        'HttpTraceColors' => '/'
      }
      end

      it 'should not log HTTP response in color' do
        subject.on_response(sample_response)
        expect(@output).to eq http_trace_no_color_response_output
      end
    end

    context 'when HttpTraceColors is set to only one color without "/"' do
      let(:mock_datastore) do {
        'HttpTrace' => true,
        'HttpTraceColors' => 'yel'
      }
      end

      it 'should not log HTTP response in color' do
        subject.on_response(sample_response)
        expect(@output).to eq http_trace_single_color_response_output
      end
    end

    context 'when HttpTraceColors is set to false' do
      let(:mock_datastore) do {
        'HttpTrace' => false
      }
      end

      it 'should not log HTTP response' do
        subject.on_response(sample_response)
        expect(@output).to eq nil
      end
    end

    context 'when HttpTraceColors is unset' do
      let(:mock_datastore) do {
        'HttpTrace' => nil
      }
      end

      it 'should not log HTTP response' do
        subject.on_response(sample_response)
        expect(@output).to eq nil
      end
    end
  end

end

