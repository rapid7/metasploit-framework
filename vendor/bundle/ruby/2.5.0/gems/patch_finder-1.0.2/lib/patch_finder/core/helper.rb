require 'net/http'

module PatchFinder
  module Helper

    class PatchFinderException < RuntimeError; end

    attr_accessor :verbose

    # Prints a message if verbose is set
    #
    # @return [void]
    def print_verbose(msg = '')
      $stderr.puts "[*] #{msg}" if self.verbose
    end

    def print_verbose_error(msg='')
      print_error(msge) if self.verbose
    end

    # Prints a status message.
    #
    # @return [void]
    def print_status(msg = '')
      $stderr.puts "[*] #{msg}"
    end

    # Prints an error message.
    #
    # @return [void]
    def print_error(msg = '')
      $stderr.puts "[ERROR] #{msg}"
    end

    # Prints a message.
    #
    # @return [void]
    def print_line(msg = '')
      $stdout.puts msg
    end

    # Sends an HTTP request.
    # @note If the request fails, it will try 3 times before
    #       passing/raising an exception.
    #
    # @param uri [String] URI.
    # @param ssl [Boolean] Forces SSL option.
    # @return [Net::HTTPResponse]
    def send_http_get_request(uri, ssl = false)
      attempts = 1
      u = URI.parse(uri)
      res = nil
      ssl = u.scheme == 'https' ? true : false

      begin
        Net::HTTP.start(u.host, u.port, use_ssl: ssl) do |cli|
          req = Net::HTTP::Get.new(normalize_uri(u.request_uri))
          req['Host'] = u.host
          req['Content-Type'] = 'application/x-www-form-urlencoded'
          res = cli.request(req)
        end
      rescue Net::ReadTimeout, IOError, EOFError, Errno::ECONNRESET,
             Errno::ECONNABORTED, Errno::EPIPE, Net::OpenTimeout,
             Errno::ETIMEDOUT => e
        if attempts < 3
          sleep(5)
          attempts += 1
          retry
        else
          raise e
        end
      end

      res
    end

    # Returns the content of a file.
    #
    # @param file_path [String] File to read.
    # @return [String]
    def read_file(file_path)
      return nil unless File.exist?(file_path)

      buf = ''

      File.open(file_path, 'rb') do |f|
        buf = f.read
      end

      buf
    end

    # Downloads a file to a local directory.
    # @note When the file is saved, the file name will actually include a timestamp
    #       in this format: [original filename]_[timestamp].[ext] to avoid
    #       name collision.
    #
    # @param uri [String] URI (to download)
    # @param dest_dir [String] The folder to save the file.
    #                          Make sure this folder exists.
    # @return [void]
    def download_file(uri, dest_dir)
      begin
        u = URI.parse(uri)
        fname, ext = File.basename(u.path).scan(/(.+)\.(.+)/).flatten
        dest_file = File.join(dest_dir, "#{fname}_#{Time.now.to_i}.#{ext}")
        res = send_http_get_request(uri)
      rescue Net::ReadTimeout, IOError, EOFError, Errno::ECONNRESET,
             Errno::ECONNABORTED, Errno::EPIPE, Net::OpenTimeout,
             Errno::ETIMEDOUT => e
        print_error("#{e.message}: #{uri}")
        return
      end

      save_file(res.body, dest_file)
      print_status("Download completed for #{uri}")
    end

    # Downloads multiple files to a local directory.
    # @note 3 clients are used to download all the links.
    #
    # @param files [Array] Full URIs.
    # @param dest_dir [String] The folder to save the files.
    #                          Make sure this folder exists.
    # @return pvoid
    def download_files(files, dest_dir)
      pool = PatchFinder::ThreadPool.new(3)

      files.each do |f|
        pool.schedule do
          download_file(f, dest_dir)
        end
      end

      pool.shutdown

      sleep(0.5) until pool.eop?
    end

    private

    # Saves a file to a specific location.
    #
    # @param data [String]
    # @param dest_file [String]
    # @return [void]
    def save_file(data, dest_file)
      File.open(dest_file, 'wb') do |f|
        f.write(data)
      end
    end

    # Returns the normalized URI by modifying the double slashes.
    #
    # @param strs [Array] URI path.
    # @return [String]
    def normalize_uri(*strs)
      new_str = strs * '/'
      new_str = new_str.gsub!('//', '/') while new_str.index('//')
      new_str
    end

  end
end
