# -*- coding: binary -*-

require 'rex/socket'

module Rex
  module Proto
    module Ftp
      ##
      #
      # Anonymous-only, in-memory FTP server.
      # Designed for use as a fetch-payload delivery server.
      #
      ##
      class Server

        def self.hardcore_alias(port, host, *_rest)
          "#{host}-#{port}"
        end

        def alias
          @alias || 'FTP Server'
        end

        def initialize(port = 21, host = '0.0.0.0', context = {})
          self.listen_port = port
          self.listen_host = host
          self.context = context
          self.files = {}
          self.serve_once = {}
          self.files_mutex = Mutex.new
          self.shutting_down = false
          self.listener = nil
          self.monitor_thread = nil
        end

        def register_file(filename, data, serve_once: true)
          files_mutex.synchronize do
            files[filename] = data
            self.serve_once[filename] = serve_once
          end
        end

        def deregister_file(filename)
          files_mutex.synchronize do
            files.delete(filename)
            serve_once.delete(filename)
          end
        end

        def start
          self.listener = Rex::Socket::TcpServer.create(
            'LocalHost' => listen_host,
            'LocalPort' => listen_port,
            'Context' => context
          )
          self.monitor_thread = Rex::ThreadFactory.spawn('FTPServerMonitor', false) do
            monitor_socket
          end
        end

        def stop
          self.shutting_down = true
          begin
            monitor_thread&.kill
          rescue StandardError
            nil
          end
          begin
            listener&.close
          rescue StandardError
            nil
          end
        end

        attr_accessor :listen_port, :listen_host, :context, :files, :serve_once, :files_mutex, :shutting_down, :listener, :monitor_thread

        private

        def monitor_socket
          until shutting_down
            begin
              client = listener.accept
              Rex::ThreadFactory.spawn('FTPServerClientHandler', false) do
                handle_client(client)
              end
            rescue StandardError
              break if shutting_down
            end
          end
        end

        def handle_client(client)
          state = {
            auth: false,
            cwd: '/',
            mode: :passive,
            active_host: client.peerhost,
            active_port: 20,
            passive_sock: nil
          }

          client.put("220 FTP Server Ready\r\n")

          until shutting_down
            data = client.get_once
            break unless data

            cmd, arg = data.strip.split(/\s+/, 2)
            arg ||= ''
            next unless cmd

            case cmd.upcase
            when 'USER'
              client.put("331 Guest login ok, send your email as password.\r\n")

            when 'PASS'
              state[:auth] = true
              client.put("230 Guest login ok.\r\n")

            when 'QUIT'
              client.put("221 Goodbye.\r\n")
              break

            when 'SYST'
              client.put("215 UNIX Type: L8\r\n")

            when 'TYPE'
              client.put("200 Type set to #{arg}.\r\n")

            when 'MODE'
              client.put("200 Mode set to #{arg}.\r\n")

            when 'PWD', 'XPWD'
              client.put("257 \"#{state[:cwd]}\" is current directory.\r\n")

            when 'CWD'
              state[:cwd] = arg.start_with?('/') ? arg : "#{state[:cwd].chomp('/')}/#{arg}"
              client.put("250 Directory successfully changed.\r\n")

            when 'CDUP'
              state[:cwd] = ::File.dirname(state[:cwd])
              client.put("250 Directory successfully changed.\r\n")

            when 'PASV'
              begin
                state[:passive_sock]&.close
              rescue StandardError
                nil
              end
              state[:passive_sock] = Rex::Socket::TcpServer.create(
                'LocalHost' => '0.0.0.0',
                'LocalPort' => 0,
                'Context' => context
              )
              dport = state[:passive_sock].getsockname[2]
              daddr = Rex::Socket.source_address(client.peerhost)
              state[:mode] = :passive
              pasv = (daddr.split('.') + [dport].pack('n').unpack('CC')).join(',')
              client.put("227 Entering Passive Mode (#{pasv}).\r\n")

            when 'PORT'
              parts = arg.split(',')
              if parts.length == 6
                state[:active_host] = parts[0..3].join('.')
                state[:active_port] = (parts[4].to_i * 256) + parts[5].to_i
                state[:mode] = :active
                client.put("200 PORT command successful.\r\n")
              else
                client.put("500 Illegal PORT command.\r\n")
              end

            when 'NOOP'
              client.put("200 NOOP ok.\r\n")

            when 'FEAT'
              client.put("211-Features:\r\n PASV\r\n211 End\r\n")

            when 'SIZE'
              filename = ::File.basename(arg)
              size = files_mutex.synchronize { files[filename]&.bytesize }
              if size
                client.put("213 #{size}\r\n")
              else
                client.put("550 No such file or directory.\r\n")
              end

            when 'LIST', 'NLST'
              unless state[:auth]
                client.put("530 Not logged in.\r\n")
                next
              end
              data_conn = establish_data_connection(client, state)
              unless data_conn
                client.put("425 Can't open data connection.\r\n")
                next
              end
              listing = files_mutex.synchronize do
                files.map do |f, d|
                  "-rwxr-xr-x   1 0      0       #{d.bytesize} Jan  1  2000 #{f}\r\n"
                end.join
              end
              client.put("150 Here comes the directory listing.\r\n")
              data_conn.put(listing)
              data_conn.close
              client.put("226 Directory send OK.\r\n")

            when 'RETR'
              unless state[:auth]
                client.put("530 Not logged in.\r\n")
                next
              end
              filename = ::File.basename(arg)
              file_data, once = files_mutex.synchronize do
                next [nil, nil] unless files.key?(filename)

                data = files[filename]
                once = serve_once[filename]
                if once
                  files.delete(filename)
                  serve_once.delete(filename)
                end
                [data, once]
              end
              unless file_data
                client.put("550 No such file or directory.\r\n")
                next
              end
              data_conn = establish_data_connection(client, state)
              unless data_conn
                if once
                  files_mutex.synchronize do
                    files[filename] = file_data
                    serve_once[filename] = true
                  end
                end
                client.put("425 Can't open data connection.\r\n")
                next
              end
              client.put("150 Opening BINARY mode data connection for #{filename}.\r\n")
              data_conn.put(file_data)
              data_conn.close
              client.put("226 Transfer complete.\r\n")

            when /^(STOR|MKD|RMD|DELE|RNFR|RNTO|APPE|STOU)$/
              client.put("550 Permission denied.\r\n")

            else
              client.put("502 Command not implemented.\r\n")
            end
          end
        rescue StandardError
          # client disconnect or other error
        ensure
          begin
            state[:passive_sock]&.close
          rescue StandardError
            nil
          end
          begin
            client.close
          rescue StandardError
            nil
          end
        end

        def establish_data_connection(client, state)
          Timeout.timeout(20) do
            if state[:mode] == :passive && state[:passive_sock]
              conn = state[:passive_sock].accept
              begin
                state[:passive_sock].close
              rescue StandardError
                nil
              end
              state[:passive_sock] = nil
              conn
            else
              Rex::Socket::Tcp.create(
                'PeerHost' => state[:active_host],
                'PeerPort' => state[:active_port],
                'Context' => context
              )
            end
          end
        rescue StandardError
          nil
        end
      end
    end
  end
end
