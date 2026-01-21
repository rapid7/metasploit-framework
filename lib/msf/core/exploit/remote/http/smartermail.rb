# -*- coding: binary -*-

module Msf
  class Exploit
    class Remote
      module HTTP
        module Smartermail
          def check_version(patched_version, low_bound = 0)
            print_status('Checking target web server for a response...')
            res = send_request_cgi!({
                                      'method' => 'GET',
                                      'uri' => normalize_uri(target_uri.path)
                                    })

            if res
              body = res.body
            else
              return CheckCode::Unknown('Target did not respond to check request.')
            end

            unless res.code == 200 && body.downcase.include?('smartermail')
              return CheckCode::Unknown('Target is not running SmarterMail.')
            end

            print_good('Target is running SmarterMail.')

            print_status('Checking SmarterMail product version...')
            product_version = body.match('stProductVersion.*')
            version_number = product_version.to_s.split('"')[1] if product_version

            unless product_version
              return CheckCode::Detected('SmarterMail product version cannot be determined.')
            end

            print_good("Target is running SmarterMail Version #{version_number}.")

            if Rex::Version.new(version_number) < Rex::Version.new(patched_version) && Rex::Version.new(version_number) >= Rex::Version.new(low_bound)
              return CheckCode::Appears('SmarterMail version is vulnerable.')
            end

            return CheckCode::Safe('SmarterMail version is patched or not vulnerable.')

          end
        end
      end
    end
  end
end
