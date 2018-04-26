# -*- coding: binary -*-

require 'rex/socket'

module Rex
  module Proto
    module Ftp
      ###
      #
      # Acts as a client to an FTP server
      # See the RFC: https://www.w3.org/Protocols/rfc959/
      #
      ###
      class Client
        #
        # Creates a new client instance.
        #
        def initialize(host, port = 21, ssl = nil, ssl_version = nil, proxies = nil, username = '', password = '', verbose = false)
          self.hostname = host
          self.port     = port.to_i
          self.context  = context
          self.ssl      = ssl
          self.ssl_version = ssl_version
          self.proxies  = proxies
          self.username = username
          self.password = password
          self.verbose  = verbose
        end

        #
        # This method estabilishes a connection to the host on the port
        # defined in opts{}, if the connection is successful, the method
        # returns a socket which can be used to communicate with the client
        #
        def connect
          nsock = Rex::Socket::Tcp.create(
            'PeerHost'      =>  self.hostname,
            'PeerPort'      =>  self.port,
            'LocalHost'     => "0.0.0.0",
            'LocalPort'     =>  0.to_i,
            'SSL'           =>  self.ssl,
            'SSLVersion'    =>  self.ssl_version,
            'Proxies'       => self.proxies
          )
          self.sock = nsock
          self.banner = recv_ftp_resp(nsock)
          print_status("Connected to target FTP server.") if self.verbose
          nsock
        end

        #
        # This method reads an FTP response based on FTP continuation
        #
        def recv_ftp_resp(nsock = self.sock)
          found_end = false
          resp = ""
          left = ""
          if !@ftpbuff.empty?
            left << @ftpbuff
            @ftpbuff = ""
          end
          while true
            data = nsock.get_once(-1, ftp_timeout)
            if !data
              @ftpbuff << resp
              @ftpbuff << left
              return data
            end

            got = left + data
            left = ""

            # handle the end w/o newline case
            enlidx = got.rindex(0x0a.chr)
            if enlidx != (got.length - 1)
              if !enlidx
                left << got
                next
              else
                left << got.slice!((enlidx + 1)..got.length)
              end
            end

            # split into lines
            rarr = got.split(/\r?\n/)
            rarr.each do |ln|
              if !found_end
                resp << ln
                resp << "\r\n"
                if ln.length > 3 && ln[3, 1] == ' '
                  found_end = true
                end
              else
                left << ln
                left << "\r\n"
              end
            end
            if found_end
              @ftpbuff << left
              print_status("FTP recv: #{resp.inspect}") if self.verbose
              return resp
            end
          end
        end

        #
        # This method transmits a FTP command and does not wait for a response
        #
        def raw_send(cmd, nsock = self.sock)
          print_status("FTP send: #{cmd.inspect}") if self.verbose
          nsock.put(cmd)
        end

        #
        # This method transmits a FTP command and waits for a response.  If one is
        # received, it is returned to the caller.
        #
        def raw_send_recv(cmd, nsock = self.sock)
          nsock.put(cmd)
          nsock.get_once(-1, ftp_timeout)
        end

        #
        # This method uses the senduser and sendpass methods defined below
        # in order to login to the ftp server
        #
        def connect_login
          ftpsock = connect

          if !(self.user && self.pass)
            print_error("No username and password were supplied, unable to login")
            return false
          end

          print_status("Authenticating as #{user} with password #{pass}...") if self.verbose
          res = send_user(user, ftpsock)

          if res !~ /^(331|2)/
            print_error("The server rejected our username") if self.verbose
            return false
          end

          if pass
            print_status("Sending password...") if self.verbose
            res = send_pass(pass, ftpsock)
            if res !~ /^2/
              print_error("The server rejected our password") if self.verbose
              return false
            end
          end

          true
        end

        #
        # This method logs in as the supplied user by transmitting the FTP
        # 'USER <user>' command.
        #
        def send_user(user, nsock = self.sock)
          raw_send("USER #{user}\r\n", nsock)
          recv_ftp_resp(nsock)
        end

        #
        # This method completes user authentication by sending the supplied
        # password using the FTP 'PASS <pass>' command.
        #
        def send_pass(pass, nsock = self.sock)
          raw_send("PASS #{pass}\r\n", nsock)
          recv_ftp_resp(nsock)
        end

        #
        # This method handles establishing datasocket for data channel
        #
        def data_connect(mode = nil, nsock = self.sock)
          if mode
            res = send_cmd([ 'TYPE', mode ], true, nsock)
            return nil if not res =~ /^200/
          end

          # force datasocket to renegotiate
          self.datasocket.shutdown if self.datasocket != nil

          res = send_cmd(['PASV'], true, nsock)
          return nil if not res =~ /^227/

          # 227 Entering Passive Mode (127,0,0,1,196,5)
          if res =~ /\((\d+)\,(\d+),(\d+),(\d+),(\d+),(\d+)/
            # convert port to FTP syntax
            datahost = "#{$1}.#{$2}.#{$3}.#{$4}"
            dataport = ($5.to_i * 256) + $6.to_i
            self.datasocket = Rex::Socket::Tcp.create(
              'PeerHost' => datahost,
              'PeerPort' => dataport
            )
          end
          self.datasocket
        end

        #
        # This method handles disconnecting our data channel
        #
        def data_disconnect
          self.datasocket.shutdown if self.datasocket
          self.datasocket = nil
        end

        #
        # This method sends one command with zero or more parameters
        #
        def send_cmd(args, recv = true, nsock = self.sock)
          cmd = args.join(" ") + "\r\n"
          ret = raw_send(cmd, nsock)
          if recv
            return recv_ftp_resp(nsock)
          end
          ret
        end

        #
        # This method sends a QUIT command.
        #
        def send_quit(nsock = self.sock)
          raw_send("QUIT\r\n", nsock)
          recv_ftp_resp(nsock)
        end

        #
        # This method transmits the command in args and receives / uploads DATA via data channel
        # For commands not needing data, it will fall through to the original send_cmd
        #
        # For commands that send data only, the return will be the server response.
        # For commands returning both data and a server response, an array will be returned.
        #
        # NOTE: This function always waits for a response from the server.
        #
        def send_cmd_data(args, data, mode = 'a', nsock = self.sock)
          type = nil
          # implement some aliases for various commands
          if args[0] =~ /^DIR$/i || args[0] =~ /^LS$/i
            # TODO || args[0] =~ /^MDIR$/i || args[0] =~ /^MLS$/i
            args[0] = "LIST"
            type = "get"
          elsif args[0] =~ /^GET$/i
            args[0] = "RETR"
            type = "get"
          elsif args[0] =~ /^PUT$/i
            args[0] = "STOR"
            type = "put"
          end

          # fall back if it's not a supported data command
          if !type
            return send_cmd(args, true, nsock)
          end

          # Set the transfer mode and connect to the remove server
          return nil if !data_connect(mode)

          # Our pending command should have got a connection now.
          res = send_cmd(args, true, nsock)
          # make sure could open port
          return nil unless res =~ /^(150|125) /

          # dispatch to the proper method
          if type == "get"
            # failed listings jsut disconnect..
            begin
              data = self.datasocket.get_once(-1, ftp_timeout)
            rescue ::EOFError
              data = nil
            end
          else
            sent = self.datasocket.put(data)
          end

          # close data channel so command channel updates
          data_disconnect

          # get status of transfer
          ret = nil
          if type == "get"
            ret = recv_ftp_resp(nsock)
            ret = [ ret, data ]
          else
            ret = recv_ftp_resp(nsock)
          end

          ret
        end

        #
        # Function implementing 'ls' or list files command
        #
        def ls
          datasocket = data_connect
          send_cmd(["list"])
          output = datasocket.get
          data_disconnect
          output
        end

        #
        # Function implementing 'pwd' or present working directory command
        #
        def pwd
          send_cmd(["pwd"])
        end

        #
        # Function implementing 'cd' or change directory command
        #
        def cd(path)
          send_cmd(["cwd " + path])
        end

        #
        # Function implementing download command
        #
        def download(filename)
          datasocket = data_connect
          send_cmd(["retr", filename])
          output = datasocket.get
          file = File.open(filename, "wb")
          file.write(output)
          file.close
          data_disconnect
        end

        #
        # Function implementing upload command
        #
        def upload
          datasocket = data_connect
          file = File.open(filename, "rb")
          data = file.read
          file.close
          send_cmd(["stor", filename])
          datasocket.write(data)
          data_disconnect
        end
      end
    end
  end
end
