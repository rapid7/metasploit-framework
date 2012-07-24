module Rex
module CloudCracker
  class HashJob < Job
    attr_accessor :hashes_file, :email, :dictionary, :dictionary_size
    attr_accessor :format, :parent_mechanism, :parent_mechanism_version

    #this method calls its parent's submit_job
    def submit_hash_job
      opts = {}

      opts[:format] = @format
      opts[:file] = @hashes_file
      opts[:email] = @email
      opts[:dictionary] = @dictionary
      opts[:dictionary_size] = @dictionary_size
      opts[:mechanism] = @parent_mechanism
      opts[:mechanism_version] = @parent_mechanism_version

      #res will be a hash of our new job information, or an error
      res = submit_job('hash', opts)

      return res
    end
  end
end
end
