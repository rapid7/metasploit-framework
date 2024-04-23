# -*- coding: binary -*-

module Msf
  class Exploit
    class Remote
      module HTTP
        # This module provides a way of logging into Apache Solr
        module ApacheSolr

          # make sending requests easier
          def solr_get(opts = {})
            send_request_cgi_opts = {
              'method' => 'GET',
              'connection' => 'Keep-Alive',
              'uri' => opts['uri']
            }.merge(opts)

            # @auth_string defaults to "" if no authentication is necessary
            # otherwise, authentication is required
            if opts['auth'] != ''
              send_request_cgi_opts.store('authorization', opts['auth'])
            end

            # a bit unrefined, but should suffice in this case
            if opts['vars_get']
              send_request_cgi_opts.store('vars_get', opts['vars_get'])
            end

            send_request_cgi(send_request_cgi_opts)
          end

          def solr_post(opts = {})
            send_request_cgi_opts = {
              'method' => 'POST',
              'connection' => 'Keep-Alive',
              'uri' => opts['uri']
            }.merge(opts)

            # @auth_string defaults to "" if no authentication is necessary
            # otherwise, authentication is required
            if opts['auth'] != ''
              send_request_cgi_opts.store('authorization', opts['auth'])
            end

            # a bit unrefined, but should suffice in this case
            if opts['vars_get']
              send_request_cgi_opts.store('vars_get', opts['vars_get'])
            end

            if opts['vars_post']
              send_request_cgi_opts.store('vars_get', opts['vars_post'])
            end

            send_request_cgi(send_request_cgi_opts)
          end


          def solr_check_auth
            # see if authentication is required for the specified Solr instance
            auth_check = solr_get(
              'uri' => normalize_uri(target_uri.path, '/admin/info/system'),
              'vars_get' => { 'wt' => 'json' }
            )

            # successfully connected?
            unless auth_check
              print_bad('Connection failed!')
              return nil
            end

            # if response code is not 200, then the Solr instance definitely requires authentication
            unless auth_check.code == 200
              # if authentication is required and creds are not provided, we cannot reliably check exploitability
              if datastore['USERNAME'] == '' && datastore['PASSWORD'] == ''
                print_bad('Credentials not provided, skipping credentialed check...')
                return nil
              end

              # otherwise, try the given creds
              auth_string = basic_auth(datastore['USERNAME'], datastore['PASSWORD'])
              attempt_auth = solr_get(
                'uri' => normalize_uri(target_uri.path, '/admin/info/system'),
                'vars_get' => { 'wt' => 'json' },
                'auth' => auth_string
              )

              # successfully connected?
              unless attempt_auth
                print_bad('Connection failed!')
                return nil
              end

              # if the return code is not 200, then authentication definitely failed
              unless attempt_auth.code == 200
                print_bad('Invalid credentials!')
                return nil
              end

              store_valid_credential(
                user: datastore['USERNAME'],
                private: datastore['PASSWORD'],
                private_type: :password,
                proof: attempt_auth.to_s
              )

              @auth_string = auth_string
              # return the response for use in check/exploit
              return attempt_auth
            end

            print_status("#{peer}: Authentication not required")
            # return the response for use in check/exploit
            auth_check
          end
        end
      end
    end
  end
end
