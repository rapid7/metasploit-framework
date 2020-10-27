# -*- coding:binary -*-
require 'rex/proto/nuuo/client'

RSpec.describe Rex::Proto::Nuuo::Client do
  subject(:client) {
    described_class.new({
      protocol: protocol,
      user_session: client_user_session,
      username: client_username,
      password: client_password
    })
  }
  let(:protocol) {'tcp'}
  let(:client_user_session) {nil}
  let(:client_username) {nil}
  let(:client_password) {nil}

  describe '#connect' do
    context 'given temp is false' do
      context 'when there is no connection' do
        it 'returns a tcp connection' do
          tcp_connection = double('tcp_connection')
          allow(Rex::Socket::Tcp).to receive(:create).and_return(tcp_connection)

          expect(client.connect).to eq(tcp_connection)
        end

        it 'saves the tcp connection' do
          tcp_connection = double('tcp_connection')
          allow(Rex::Socket::Tcp).to receive(:create).and_return(tcp_connection)

          client.connect
          expect(client.connection).to eq(tcp_connection)
        end
      end

      context 'when there is saved connection' do
        it 'returns the saved tcp connection' do
          tcp_connection = double('tcp_connection')
          client.connection = tcp_connection

          expect(client.connect).to eq(tcp_connection)
        end
      end
    end

    context 'given temp is true' do
      context 'when there is a saved connection' do
        it 'returns a new connection' do
          tcp_connection0 = double('tcp_connection')
          tcp_connection1 = double('tcp_connection')
          allow(Rex::Socket::Tcp).to receive(:create).and_return(tcp_connection1)

          client.connection = tcp_connection0
          expect(client.connect(temp: true)).to eq(tcp_connection1)
        end

        it 'does not overwrite existing connection' do
          tcp_connection0 = double('tcp_connection')
          tcp_connection1 = double('tcp_connection')
          allow(Rex::Socket::Tcp).to receive(:create).and_return(tcp_connection1)

          client.connection = tcp_connection0
          client.connect(temp: true)
          expect(client.connection).to eq(tcp_connection0)
        end
      end

      context 'when there is no saved connection' do
        it 'returns a new connection' do
          tcp_connection = double('tcp_connection')
          allow(Rex::Socket::Tcp).to receive(:create).and_return(tcp_connection)

          expect(client.connect(temp: true)).to eq(tcp_connection)
        end

        it 'does not save the connection' do
          tcp_connection = double('tcp_connection')
          allow(Rex::Socket::Tcp).to receive(:create).and_return(tcp_connection)

          client.connect(temp: true)
          expect(client.connection).to be_nil
        end
      end
    end

  end

  describe '#close' do
    context 'given there is a connection' do
      it 'calls shutdown on the connection' do
        tcp_connection = double('tcp_connection')
        allow(tcp_connection).to receive(:shutdown) {true}
        allow(tcp_connection).to receive(:closed?) {false}
        allow(tcp_connection).to receive(:close) {true}
        client.connection = tcp_connection

        expect(tcp_connection).to receive(:shutdown)
        client.close
      end

      it 'calls closed on the connection' do
        tcp_connection = double('tcp_connection')
        allow(tcp_connection).to receive(:shutdown) {true}
        allow(tcp_connection).to receive(:closed?) {false}
        allow(tcp_connection).to receive(:close) {true}
        client.connection = tcp_connection

        expect(tcp_connection).to receive(:close)
        client.close
      end
    end
  end

  describe '#send_recv' do
    context 'given no connection is passed in' do
      it 'calls send_request without connection' do
        allow(client).to receive(:send_request) do |*args|
          expect(args[1]).to be_nil
        end
        allow(client).to receive(:read_response)

        client.send_recv('test')
      end

      it 'calls read_resposne without connection' do
        allow(client).to receive(:read_response) do |*args|
          expect(args[0]).to be_nil
        end
        allow(client).to receive(:send_request)

        client.send_recv('test')
      end
    end

    context 'given a connection is passed in' do
      it 'uses the passed in connection' do
        tcp_connection = double('tcp_connection')
        passed_connection = double('passed_connection')
        client.connection = tcp_connection

        allow(passed_connection).to receive(:put)
        allow(client).to receive(:read_response)

        expect(passed_connection).to receive(:put)
        client.send_recv('test', passed_connection)
      end
    end
  end

  describe '#read_response' do
    let(:res) {"NUCM/1.0 200\r\nTest:test\r\nContent-Length:1\r\n\r\na"}
    it 'returns a Response object' do
      tcp_connection = double('tcp_connection')
      allow(tcp_connection).to receive('closed?') {false}
      allow(tcp_connection).to receive('get_once') {res}
      client.connection = tcp_connection

      expect(client.read_response).to be_a_kind_of(Rex::Proto::Nuuo::Response)
    end
  end

  describe '#request_ping' do
    subject(:ping_request) {
      opts = {'user_session' => user_session}
      client.request_ping(opts)
    }
    let(:user_session) {nil}

    it 'returns a PING client request' do
      expect(ping_request.to_s).to start_with('PING')
    end

    context 'given a user_session option' do
      let(:user_session) {'test'}

      context 'when the client does not have a session' do
        it 'uses the user_session option' do
          expect(ping_request.to_s).to match('User-Session-No: test')
        end
      end

      context 'when the client has a session' do
        let(:client_user_session) {'client'}

        it 'overrides the client session value' do
          expect(ping_request.to_s).to match('User-Session-No: test')
        end
      end
    end


    context 'given no user_session is provided' do
      context 'when the client does not have a session' do
        it 'does not have a User-Session-No header' do
          expect(ping_request.to_s).to_not match('User-Session-No:')
        end
      end

      context 'when the client has a session' do
        let(:client_user_session) {'client'}

        it 'uses the client session' do
          expect(ping_request.to_s).to match('User-Session-No: client')
        end
      end
    end

  end

  describe '#request_sendlicfile' do
    subject(:sendlicfile_request) {
      opts = {
        'file_name' => filename,
        'data' => data
      }
      client.request_sendlicfile(opts).to_s
    }
    let(:filename) {'TestFile'}
    let(:data) {'testdata'}

    it 'returns a SENDLICFILE client request' do
      expect(sendlicfile_request).to start_with('SENDLICFILE')
    end

    context 'given file_name' do
      it 'sets the FileName header with the value' do
        expect(sendlicfile_request).to match("[^\r\n]\r\nFileName: TestFile\r\n")
      end
    end

    context 'given no file_name' do
      let(:filename) {nil}

      it 'creates an empty FileName header' do
        expect(sendlicfile_request).to match("[^\r\n]\r\nFileName: \r\n")
      end
    end

    context 'given data' do
      it 'sets the body to the data contents' do
        expect(sendlicfile_request).to end_with("\r\n\r\ntestdata")
      end

      it 'sets the Content-Length header with data length' do
        expect(sendlicfile_request).to match("[^\r\n]\r\nContent-Length: 8\r\n")
      end
    end

    context 'given no data' do
      let(:data) {nil}
      it 'creates an empty body' do
        expect(sendlicfile_request).to end_with("\r\n\r\n")
      end

      it 'set Content-Length header to 0' do
        expect(sendlicfile_request).to match("[^\r\n]\r\nContent-Length: 0\r\n")
      end
    end
  end

  describe '#request_getconfig' do
    subject(:getconfig_request) {
      opts = {
        'file_name' => filename,
        'file_type' => filetype
      }
      client.request_getconfig(opts).to_s
    }
    let(:filename) {'TestName'}
    let(:filetype) {2}

    it 'returns a GETCONFIG client request' do
      expect(getconfig_request).to start_with('GETCONFIG')
    end

    context 'given file_name' do
      it 'sets the FileName header' do
        expect(getconfig_request).to match("[^\r\n]\r\nFileName: TestName\r\n")
      end
    end

    context 'given no file_name' do
      let(:filename) {nil}
      it 'creates an empty FileName header' do
        expect(getconfig_request).to match("[^\r\n]\r\nFileName: \r\n")
      end
    end

    context 'given a file_type' do
      it 'sets the FileType header' do
        expect(getconfig_request).to match("[^\r\n]\r\nFileType: 2\r\n")
      end
    end

    context 'given no file_type' do
      let(:filetype) {nil}
      it 'defaults to 1' do
        expect(getconfig_request).to match("[^\r\n]\r\nFileType: 1\r\n")
      end
    end
  end

  describe '#request_commitconfig' do
    subject(:commitconfig_request) {
      opts = {
        'file_name' => filename,
        'file_type' => filetype,
        'data' => data
      }
      client.request_commitconfig(opts).to_s
    }
    let(:filename) {'TestName'}
    let(:filetype) {2}
    let(:data) {'testdata'}

    it 'returns a COMMITCONFIG client request' do
      expect(commitconfig_request).to start_with('COMMITCONFIG')
    end

    context 'given file_name' do
      it 'sets the FileName header' do
        expect(commitconfig_request).to match("[^\r\n]\r\nFileName: TestName\r\n")
      end
    end
    
    context 'given no file_name' do
      let(:filename) {nil}

      it 'creates an empty FileName header' do
        expect(commitconfig_request).to match("[^\r\n]\r\nFileName: \r\n")
      end
    end

    context 'given file_type' do
      it 'sets the FileType header' do
        expect(commitconfig_request).to match("[^\r\n]\r\nFileType: 2\r\n")
      end
    end

    context 'given no file_type' do
      let(:filetype) {nil}

      it 'creates an empty FileType header' do
        expect(commitconfig_request).to match("[^\r\n]\r\nFileType: 1\r\n")
      end
    end

    context 'given data' do
      it 'sets the request body to the data' do
        expect(commitconfig_request).to end_with("\r\n\r\ntestdata")
      end

      it 'sets Content-Length to data length' do
        expect(commitconfig_request).to match("[^\r\n]\r\nContent-Length: 8\r\n")
      end
    end

    context 'given no data' do
      let(:data) {nil}

      it 'creates an empty request body' do
        expect(commitconfig_request).to end_with("\r\n\r\n")
      end

      it 'creates Content-Length header with 0' do
        expect(commitconfig_request).to match("[^\r\n]\r\nContent-Length: 0\r\n")
      end
    end
  end

  describe '#request_userlogin' do
    subject(:userlogin_request) {
      opts = {
        'server_version' => server_version,
        'username' => username,
        'password' => password
      }
      client.request_userlogin(opts).to_s
    }
    let(:server_version) {'1.1.1'}
    let(:username) {'user'}
    let(:password) {'pass'}

    it 'returns a USERLOGIN client request' do
      expect(userlogin_request).to start_with('USERLOGIN')
    end

    context 'given server_version' do
      it 'sets Version header with value' do
        expect(userlogin_request).to match("[^\r\n]\r\nVersion: 1.1.1\r\n")
      end
    end

    context 'given no server_version' do
      let(:server_version) {nil}

      it 'creates an empty Version header' do
        expect(userlogin_request).to match("[^\r\n]\r\nVersion: \r\n")
      end
    end

    context 'when client has username' do
      let(:client_username) {'client_user'}

      context 'given username' do
        it 'sets the Username header with opts username' do
          expect(userlogin_request).to match("[^\r\n]\r\nUsername: user\r\n")
        end
      end

      context 'given no username' do
        let(:username) {nil}

        it 'creates an Username header with client username' do
          expect(userlogin_request).to match("[^\r\n]\r\nUsername: client_user\r\n")
        end
      end
    end

    context 'when client has no username' do
      context 'given username' do
        it 'sets the Username header with value' do
          expect(userlogin_request).to match("[^\r\n]\r\nUsername: user\r\n")
        end
      end

      context 'given no username' do
        let(:username) {nil}

        it 'creates an empty Username header' do
          expect(userlogin_request).to match("[^\r\n]\r\nUsername: \r\n")
        end
      end
    end

    context 'when client has password' do
      let(:client_password) {'client_pass'}

      context 'given password' do
        it 'sets body with password' do
          expect(userlogin_request).to end_with("\r\n\r\npass")
        end

        it 'sets Password-Length header' do
          expect(userlogin_request).to match("[^\r\n]\r\nPassword-Length: 4\r\n")
        end
      end

      context 'given no password' do
        let(:password) {nil}

        it 'sets body to client password' do
          expect(userlogin_request).to end_with("\r\n\r\nclient_pass")
        end

        it 'creates Password-Length with client password length' do
          expect(userlogin_request).to match("[^\r\n]\r\nPassword-Length: 11\r\n")
        end
      end
    end

    context 'when client has no password' do
      context 'given password' do
        it 'sets body with password' do
          expect(userlogin_request).to end_with("\r\n\r\npass")
        end

        it 'sets Password-Length header' do
          expect(userlogin_request).to match("[^\r\n]\r\nPassword-Length: 4\r\n")
        end
      end

      context 'given no password' do
        let(:password) {nil}

        it 'sets empty body' do
          expect(userlogin_request).to end_with("\r\n\r\n")
        end

        it 'creates Password-Length with 0' do
          expect(userlogin_request).to match("[^\r\n]\r\nPassword-Length: 0\r\n")
        end
      end
    end

  end

  describe '#request_getopenalarm' do
    subject(:getopenalarm_request) {
      opts = {
        'device_id' => device_id,
        'source_server' => source_server,
        'last_one' => last_one
      }
      client.request_getopenalarm(opts).to_s
    }
    let(:device_id) {nil}
    let(:source_server) {nil}
    let(:last_one) {nil}

    it 'returns a GETOPENALARM client request' do
      expect(getopenalarm_request).to start_with('GETOPENALARM')
    end

    context 'given device_id' do
      let(:device_id) {2}

      it 'sets DeviceID header with value' do
        expect(getopenalarm_request).to match("[^\r\n]\r\nDeviceID: 2\r\n")
      end
    end

    context 'given no device_id' do
      it 'sets DeviceID header to 1' do
        expect(getopenalarm_request).to match("[^\r\n]\r\nDeviceID: 1\r\n")
      end
    end

    context 'given source_server' do
      let(:source_server) {2}

      it 'sets SourceServer header with value' do
        expect(getopenalarm_request).to match("[^\r\n]\r\nSourceServer: 2\r\n")
      end
    end

    context 'given no source_server' do
      it 'set SourceServer header to 1' do
        expect(getopenalarm_request).to match("[^\r\n]\r\nSourceServer: 1\r\n")
      end
    end

    context 'given last_one' do
      let(:last_one) {2}

      it 'sets LastOne header with value' do
        expect(getopenalarm_request).to match("[^\r\n]\r\nLastOne: 2\r\n")
      end
    end

    context 'given no last_one' do
      it 'sets LastOne to 1' do
        expect(getopenalarm_request).to match("[^\r\n]\r\nLastOne: 1\r\n")
      end
    end
  end
end
