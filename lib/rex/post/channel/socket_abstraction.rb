# -*- coding: binary -*-

module Rex
  module Post
    module Channel
      module SocketAbstraction
        ###
        #
        # This interface is meant to be included by channelized sockets. It updates
        # their getname methods to correctly report the information based on the
        # channel object (which must have a `#params` attribute).
        #
        ###
        module SocketInterface
          include Rex::Socket

          def getsockname
            return super unless channel

            # Find the first host in our chain (our address)
            hops = 0
            csock = channel.client.sock
            while csock.respond_to?('channel')
              csock = csock.channel.client.sock
              hops += 1
            end
            _address_family, caddr, _cport = csock.getsockname
            address_family, raddr, _rport = csock.getpeername_as_array
            _maddr = channel.params.localhost
            mport = channel.params.localport
            [ address_family, "#{caddr}#{(hops > 0) ? "-_#{hops}_" : ''}-#{raddr}", mport ]
          end

          def getpeername
            return super if !channel

            maddr = channel.params.peerhost
            mport = channel.params.peerport
            ::Socket.sockaddr_in(mport, maddr)
          end

          %i[localhost localport peerhost peerport].map do |meth|
            define_method(meth) do
              return super if !channel

              channel.params.send(meth)
            end
          end

          def close
            super
            channel.cleanup_abstraction
            channel.close
          end

          attr_accessor :channel
        end
      end
    end
  end
end
