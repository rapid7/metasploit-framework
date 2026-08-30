module Msf
  ###
  #
  # This module exposes methods for querying a remote LDAP service
  #
  ###
  module Exploit::Remote::LDAP::ActiveDirectory

    module AdCsOpts


      def initialize(info = {})
        super

        register_options([
                           OptString.new('ADD_CERT_APP_POLICY', [ false, 'Add certificate application policy OIDs' ], regex: /^\d+(\.\d+)+(([;,]\s*|\s+)\d+(\.\d+)+)*$/),
                           OptString.new('ALT_DNS', [ false, 'Alternative certificate DNS' ]),
                           OptString.new('ALT_SID', [ false, 'Alternative object SID' ]),
                           OptString.new('ALT_UPN', [ false, 'Alternative certificate UPN (format: USER@DOMAIN)' ]),
                           OptString.new('CERT_TEMPLATE', [ true, 'The certificate template', 'User' ]),
                           OptPath.new('PFX', [ false, 'Certificate to request on behalf of' ]),
                           OptString.new('ON_BEHALF_OF', [ false, 'Username to request on behalf of (format: DOMAIN\\USER)' ]),
                         ])
        register_advanced_options([
                                    OptEnum.new('DigestAlgorithm', [ true, 'The digest algorithm to use', 'SHA256', %w[SHA1 SHA256] ]),
                                    OptEnum.new('RSAKeySize', [ true, 'RSA key size in bits for CSR generation', '2048', %w[1024 2048 3072 4096 8192] ])
                                  ])
      end

      def validate
        errors = {}
        if datastore['ALT_SID'].present? && datastore['ALT_SID'] !~ /^S(-\d+)+$/
          errors['ALT_SID'] = 'Must be a valid SID.'
        end

        if datastore['ALT_UPN'].present? && datastore['ALT_UPN'] !~ /^\S+@[^\s\\]+$/
          errors['ALT_UPN'] = 'Must be in the format USER@DOMAIN.'
        end

        if datastore['ON_BEHALF_OF'].present?
          errors['ON_BEHALF_OF'] = 'Must be in the format DOMAIN\\USER.' unless datastore['ON_BEHALF_OF'] =~ /^[^\s@]+\\\S+$/
          errors['PFX'] = 'A PFX file is required when ON_BEHALF_OF is specified.' if datastore['PFX'].blank?
        end

        if datastore['PFX'].present?
          begin
            OpenSSL::PKCS12.new(File.binread(datastore['PFX']))
          rescue StandardError => e
            errors['PFX'] = "Failed to load the PFX file (#{e})"
          end
        end

        raise OptionValidateError, errors unless errors.empty?

        super
      end
    end
  end
end
