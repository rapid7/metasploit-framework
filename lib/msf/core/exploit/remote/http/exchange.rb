# -*- coding: binary -*-

module Msf
  class Exploit
    class Remote
      module HTTP
        # This module provides a way of interacting with Exchange installations
        module Exchange
          include Msf::Exploit::Remote::HttpClient

          # Build the array of Exchange Servers using the JSON file at data/exchange_versions.json. If the array has already been built then return it.
          #
          # @return [Array] Array of Exchange Server versions retrieved from the data/exchange_versions.json JSON file.
          def get_exchange_builds
            # If we already built the exchange builds array, then just return it.
            return @exchange_builds if @exchange_builds

            @exchange_builds = []
            raw_exchange_build_json = JSON.parse(File.read(::File.join(Msf::Config.data_directory, 'exchange_versions.json'), mode: 'rb'))

            for server_version in raw_exchange_build_json['exchange_builds']
              for build in server_version['builds']
                @exchange_builds << build
              end
            end
          end

          # Determine if the target is running Exchange Server or not
          #
          # @return [Boolean] True if the target is running Exchange Server, false if not.
          def target_running_exchange?
            res = send_request_cgi(
              'method' => 'GET',
              'uri' => normalize_uri(target_uri.path, '/owa/auth/logon.aspx')
            )

            unless res
              print_error('Target did not respond!')
              return false
            end

            if res && res.code == 200 && (res.body =~ /function IsOwaPremiumBrowser/ || res.body =~ /To use Outlook, browser settings must allow scripts to run./)
              print_status('Target is an Exchange Server!')
              true
            else
              print_status('Target is NOT an Exchange Server!')
              false
            end
          end

          # Get the Exchange version number.
          #
          # @see https://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates Exchange Version Numbers
          #
          # @param exchange_builds [Array] Array containing vulnerable build numbers to check for. Used to narrow scope of brute force approach used if all other enumeration approaches fail.
          # @return [Rex::Version, nil] The Exchange version if it was able to be recovered. Nil otherwise
          def exchange_get_version(exchange_builds: nil)
            # First check target is actually Exchange
            return nil unless target_running_exchange?

            # If no exchange_builds parameter, call get_exchange_builds to build the Exchange version array.
            # Otherwise use supplied exchange_builds parameter after first checking to make sure its a non-empty Array.
            exchange_builds = get_exchange_builds if !exchange_builds.is_a?(Array) || exchange_builds.nil?

            # Unless lets try a cheap way of doing this via a leak of the X-OWA-Version header.
            # If we get this we know the version number for sure and we can skip a lot of leg work.
            res = send_request_cgi(
              'method' => 'GET',
              'uri' => normalize_uri(target_uri.path, '/owa/service')
            )

            unless res
              print_error('Target did not respond!')
              return nil
            end

            if res.headers['X-OWA-Version']
              build = res.headers['X-OWA-Version']
              return Rex::Version.new(build)
            end

            # Next, determine if we are up against an older version of Exchange Server where
            # the /owa/auth/logon.aspx page gives the full version. Recent versions of Exchange
            # give only a partial version without the build number.
            res = send_request_cgi(
              'method' => 'GET',
              'uri' => normalize_uri(target_uri.path, '/owa/auth/logon.aspx')
            )

            unless res
              print_error('Target did not respond!')
              return nil
            end

            if res.code == 200 && res.body =~ %r{/owa/(?>auth/)?(?<build>\d+(?>\.\d+){3})}
              return Rex::Version.new(Regexp.last_match('build'))
            end

            # Next try @tseller's way and try /ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application
            # URL which if successful should provide some XML with entries like the following:
            #
            # <assemblyIdentity name="microsoft.exchange.ediscovery.exporttool.application"
            # version="15.2.986.5" publicKeyToken="b1d1a6c45aa418ce" language="neutral"
            # processorArchitecture="msil" xmlns="urn:schemas-microsoft-com:asm.v1" />
            #
            # This only works on Exchange Server 2013 and later and may not always work, but if it
            # does work it provides the full version number so its a nice strategy.
            res = send_request_cgi(
              'method' => 'GET',
              'uri' => normalize_uri(target_uri.path, '/ecp/current/exporttool/microsoft.exchange.ediscovery.exporttool.application')
            )

            unless res
              print_error('Target did not respond!')
              return nil
            end

            if res.code == 200 && res.body =~ /name="microsoft.exchange.ediscovery.exporttool" version="(?<build>\d+(?>\.\d+){3})"/
              return Rex::Version.new(Regexp.last_match('build'))
            end

            # Finally, try a variation on the above and use a well known trick of grabbing /owa/auth/logon.aspx
            # to get a partial version number, then use the URL at /ecp/<version here>/exporttool/. If we get a 200
            # OK response, we found the target version number, otherwise we didn't find it.
            #
            # Props go to @jmartin-r7 for improving my original code for this and suggestion the use of
            # canonical_segments to make this close to the Rex::Version code format. Also for noticing that
            # version_range is a Rex::Version object already and cleaning up some of my original code to simplify
            # things on this premise.

            exchange_builds.each do |version|
              res = send_request_cgi(
                'method' => 'GET',
                'uri' => normalize_uri(target_uri.path, "/ecp/#{version}/exporttool/")
              )

              unless res
                print_error('Target did not respond!')
                return nil
              end

              if res && res.code == 200
                return Rex::Version.new(version)
              end
            end

            # If we reach here we couldn't find the Exchange Server version, so just return nil to indicate this.
            nil
          end
        end
      end
    end
  end
end
