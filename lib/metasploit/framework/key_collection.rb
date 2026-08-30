module Metasploit::Framework
  class KeyCollection < Metasploit::Framework::CredentialCollection
    attr_accessor :key_data
    attr_accessor :key_path
    attr_accessor :private_key
    attr_accessor :error_list
    attr_accessor :ssh_keyfile_b64

    # Override CredentialCollection#has_privates?
    def has_privates?
      @key_data.present?
    end

    def realm
      nil
    end

    def valid?
      @error_list = []
      @key_data = Set.new

      if @private_key.present?
        results = validate_private_key(@private_key)
      elsif @key_path.present?
        results = validate_key_path(@key_path)
      else
        @error_list << 'No key path or key provided'
        raise RuntimeError, 'No key path or key provided'
      end

      if results[:key_data].present?
        @key_data.merge(results[:key_data])
      else
        @error_list.concat(results[:error_list]) if results[:error_list].present?
      end

      @key_data.present?
    end

    def validate_private_key(private_key)
      key_data = Set.new
      error_list = []
      begin
        if Net::SSH::KeyFactory.load_data_private_key(private_key, @password, false).present?
          key_data << private_key
        end
      rescue StandardError => e
        error_list << "Error validating private key: #{e}"
      end
      {key_data: key_data, error_list: error_list}
    end

    def validate_key_path(key_path)
      key_data = Set.new
      error_list = []

      if File.file?(key_path)
        key_files = [key_path]
      elsif File.directory?(key_path)
        key_files = Dir.entries(key_path).reject { |f| f =~ /^\x2e|\x2epub$/ }.map { |f| File.join(key_path, f) }
      else
        return {key_data: nil, error: "#{key_path} Invalid key path"}
      end

      key_files.each do |f|
        begin
          if read_key(f).present?
            key_data << File.read(f)
          end
        rescue StandardError => e
          error_list << "#{f}: #{e}"
        end
      end
      {key_data: key_data, error_list: error_list}
    end


    def each
      prepended_creds.each { |c| yield c }

      if @user_file.present?
        File.open(@user_file, 'rb') do |user_fd|
          user_fd.each_line do |user_from_file|
            user_from_file.chomp!
            each_key do |key_data|
              yield Metasploit::Framework::Credential.new(public: user_from_file, private: key_data, realm: realm, private_type: :ssh_key)
            end
          end
        end
      end

      if @username.present?
        each_key do |key_data|
          yield Metasploit::Framework::Credential.new(public: @username, private: key_data, realm: realm, private_type: :ssh_key)
        end
      end
    end

    def each_key
      @key_data.each do |data|
        yield data
      end
    end

    def read_key(file_path)
      @cache ||= {}
      @cache[file_path] ||= Net::SSH::KeyFactory.load_private_key(file_path, password, false)
      @cache[file_path]
    end
  end
end
