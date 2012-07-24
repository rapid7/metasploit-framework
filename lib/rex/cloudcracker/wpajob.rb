module Rex
module CloudCracker
  class WPAJob < Job
    attr_accessor :pcap_file, :essid, :email, :dictionary, :dictionary_size
    attr_accessor :parent_mechanism, :parent_mechanism_version

    def submit_wpa_job
      opts = {}

      opts[:format] = "wpa"
      opts[:file] = @pcap_file
      opts[:email] = @email
      opts[:essid] = @essid
      opts[:dictionary] = @dictionary
      opts[:dictionary_size] = @dictionary_size
      opts[:mechanism] = @parent_mechanism
      opts[:mechanism_version] = @parent_mechanism_version

      #res will be a hash of our new job information, or an error
      res = submit_job('wpa', opts)

      return res
    end
  end
end
end
