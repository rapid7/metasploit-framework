# -*- coding: binary -*-

module Rex
  module Post
    module LDAP
      module Ui
        ###
        #
        # Core LDAP client commands
        #
        ###
        class Console::CommandDispatcher::Client

          include Rex::Post::LDAP::Ui::Console::CommandDispatcher
          include Msf::Exploit::Remote::LDAP::Queries


          OUTPUT_FORMATS = %w[table csv json]
          VALID_SCOPES = %w[base single whole]

          @@query_opts = Rex::Parser::Arguments.new(
            %w[-h --help] => [false, 'Help menu' ],
            %w[-f --filter] => [true, 'Filter string for the query (default: (objectclass=*))'],
            %w[-a --attributes] => [true, 'Comma separated list of attributes for the query'],
            %w[-b --base-dn] => [true, 'Base dn for the query'],
            %w[-s --scope] => [true, 'Scope for the query: `base`, `single`, `whole` (default: whole)'],
            %w[-o --output-format] => [true, 'Output format: `table`, `csv` or `json` (default: table)']
          )

          #
          # List of supported commands.
          #
          def commands
            cmds = {
              'query' => 'Run an LDAP query',
              'getuid' => 'Get the user that the connection is running as'
            }

            reqs = {}

            filter_commands(cmds, reqs)
          end

          #
          # Client
          #
          def name
            'Client'
          end

          #
          # Query the LDAP server
          #
          def cmd_query(*args)
            if args.include?('-h') || args.include?('--help')
              cmd_query_help
              return
            end

            attributes = []
            filter = '(objectclass=*)'
            base_dn = client.base_dn
            schema_dn = client.schema_dn
            scope = Net::LDAP::SearchScope_WholeSubtree
            output_format = 'table'
            @@query_opts.parse(args) do |opt, _idx, val|
              case opt
              when '-a', '--attributes'
                attributes.push(*val.split(','))
              when '-f', '--filter'
                filter = val
              when '-b', '--base-dn'
                base_dn = val
              when '-s', '--scope'
                scope = parse_scope(val)
                raise ArgumentError, "Invalid scope provided: #{scope}, must be one of #{VALID_SCOPES}" if scope.nil?
              when '-o', '--output-format'
                if OUTPUT_FORMATS.include?(val)
                  output_format = val
                else
                  raise ArgumentError, "Invalid output format: #{val}, must be one of #{OUTPUT_FORMATS}"
                end
              end
            rescue StandardError => e
              handle_error(e)
            end

            perform_ldap_query_streaming(client, filter, attributes, base_dn, schema_dn, scope: scope) do |result, attribute_properties|
              show_output(normalize_entry(result, attribute_properties), output_format)
            end
          end

          def cmd_query_tabs(_str, words)
            return [] if words.length > 1

            @@query_opts.option_keys
          end

          def cmd_query_help
            print_line 'Usage: query -f <filter string> -a <attributes>'
            print_line
            print_line 'Run the query against the session.'
            print @@query_opts.usage
          end

          def cmd_getuid
            begin
              username = client.ldapwhoami
            rescue Net::LDAP::Error => e
              print_error(e.message)
              return
            end
            username.delete_prefix!('u:')
            print_status("Server username: #{username}")
          end

          private

          def parse_scope(str)
            case str.downcase
            when 'base'
              Net::LDAP::SearchScope_BaseObject
            when 'single', 'one'
              Net::LDAP::SearchScope_SingleLevel
            when 'whole', 'sub'
              Net::LDAP::SearchScope_WholeSubtree
            else
              nil
            end
          end
        end
      end
    end
  end
end
