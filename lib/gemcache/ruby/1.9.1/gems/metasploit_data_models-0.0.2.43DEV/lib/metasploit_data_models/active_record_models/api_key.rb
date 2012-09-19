module MetasploitDataModels::ActiveRecordModels::ApiKey
  def self.included(base)
    base.class_eval {

      validate do |key|
        lic = License.get

        if lic and not lic.supports_api?
          key.errors[:unsupported_product] = " - this product does not support API access"
        end

        if key.token.to_s.empty?
          key.errors[:blank_token] = " - the specified authentication token is empty"
        end

        if key.token.to_s.length < 8
          key.errors[:token_too_short] = " - the specified authentication token must be at least 8 characters long"
        end
      end
    }
  end
end
