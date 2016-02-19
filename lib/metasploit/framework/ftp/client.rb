require 'metasploit/framework/tcp/client'

module Metasploit
  module Framework
    module Ftp
      module Client
        extend ActiveSupport::Concern
        include Metasploit::Framework::Tcp::Client

        #
        # This method establishes an FTP connection to host and port specified by
        # the 'rhost' and 'rport' methods. After connecting, the banner
        # message is read in and stored in the 'banner' attribute.
        #
        def connect(global = true)
          fd = super(global)

          @ftpbuff = '' unless @ftpbuff

          # Wait for a banner to arrive...
          self.banner = recv_ftp_resp(fd)

          # Return the file descriptor to the caller
          fd
        end

        #
        # This method handles establishing datasocket for data channel
        #
        def data_connect(mode = nil, nsock = self.sock)
          if mode
            res = send_cmd([ 'TYPE' , mode ], true, nsock)
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
              'PeerPort' => dataport,
              'Context'  => { 'Msf' => framework, 'MsfExploit' => framework_module }
            )
          end
          self.datasocket
        end

        #
        # This method handles disconnecting our data channel
        #
        def data_disconnect
          self.datasocket.shutdown
          self.datasocket = nil
        end

        #
        # Connect and login to the remote FTP server using the credentials
        # that have been supplied in the exploit options.
        #
        def connect_login(user,pass,global = true)
          ftpsock = connect(global)

          if !(user and pass)
            return false
          end

          res = send_user(user, ftpsock)

          if (res !~ /^(331|2)/)
            return false
          end

          if (pass)
            res = send_pass(pass, ftpsock)
            if (res !~ /^2/)
              return false
            end
          end

          return true
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
        # This method sends a QUIT command.
        #
        def send_quit(nsock = self.sock)
          raw_send("QUIT\r\n", nsock)
          recv_ftp_resp(nsock)
        end

        #
        # This method sends one command with zero or more parameters
        #
        def send_cmd(args, recv = true, nsock = self.sock)
          cmd = args.join(" ") + "\r\n"
          ret = raw_send(cmd, nsock)
          if (recv)
            return recv_ftp_resp(nsock)
          end
          return ret
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
          if (args[0] =~ /^DIR$/i || args[0] =~ /^LS$/i)
            # TODO || args[0] =~ /^MDIR$/i || args[0] =~ /^MLS$/i
            args[0] = "LIST"
            type = "get"
          elsif (args[0] =~ /^GET$/i)
            args[0] = "RETR"
            type = "get"
          elsif (args[0] =~ /^PUT$/i)
            args[0] = "STOR"
            type = "put"
          end

          # fall back if it's not a supported data command
          if not type
            return send_cmd(args, true, nsock)
          end

          # Set the transfer mode and connect to the remove server
          return nil if not data_connect(mode)

          # Our pending command should have got a connection now.
          res = send_cmd(args, true, nsock)
          # make sure could open port
          return nil unless res =~ /^(150|125) /

          # dispatch to the proper method
          if (type == "get")
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
          if (type == "get")
            ret = recv_ftp_resp(nsock)
            ret = [ ret, data ]
          else
            ret = recv_ftp_resp(nsock)
          end

          ret
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
        # This method reads an FTP response based on FTP continuation stuff
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
            if not data
              @ftpbuff << resp
              @ftpbuff << left
              return data
            end

            got = left + data
            left = ""

            # handle the end w/o newline case
            enlidx = got.rindex(0x0a.chr)
            if enlidx != (got.length-1)
              if not enlidx
                left << got
                next
              else
                left << got.slice!((enlidx+1)..got.length)
              end
            end

            # split into lines
            rarr = got.split(/\r?\n/)
            rarr.each do |ln|
              if not found_end
                resp << ln
                resp << "\r\n"
                if ln.length > 3 and ln[3,1] == ' '
                  found_end = true
                end
              else
                left << ln
                left << "\r\n"
              end
            end
            if found_end
              @ftpbuff << left
              return resp
            end
          end
        end

        #
        # This method transmits a FTP command and does not wait for a response
        #
        def raw_send(cmd, nsock = self.sock)
          nsock.put(cmd)
        end

        def ftp_timeout
          raise NotImplementedError
        end



        protected

        #
        # This attribute holds the banner that was read in after a successful call
        # to connect or connect_login.
        #
        attr_accessor :banner, :datasocket


      end
    end
  end
end
