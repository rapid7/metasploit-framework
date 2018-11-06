require 'nokogiri'
require 'patch_finder/core/thread_pool'
require 'patch_finder/engine/msu/google'
require 'patch_finder/engine/msu/technet'
require 'patch_finder/engine/msu/constants'

module PatchFinder
  class MSU

    include Helper

    MAX_THREADS = 10

    def initialize(opts={})
      self.verbose = opts[:verbose] || false
    end

    # Returns the download links.
    #
    # @param args [Hash] Arguments created by the user.
    # @return [Array]
    def find_msu_download_links(args)
      msb_numbers = collect_msbs(args)

      unless msb_numbers.empty?
        print_verbose("Advisories found (#{msb_numbers.length}): #{msb_numbers * ', '}")
        print_verbose('Please wait while the download links are being collected...')
      end

      download_links = []

      print_verbose("Max number of active collecting clients: #{MAX_THREADS}")
      pool = PatchFinder::ThreadPool.new(MAX_THREADS)

      begin
        msb_numbers.each do |msb|
          pool.schedule do
            links = collect_links_from_msb(msb, args[:regex])
            pool.mutex.synchronize do
              download_links.concat(links)
            end
          end
        end

        pool.shutdown

        sleep(0.5) until pool.eop?
      ensure
        pool.cleanup
      end

      download_links
    end

    private

    # Returns the MSBs (advisories) numbers.
    #
    # @param args [Hash]
    # @return [Array]
    def collect_msbs(args)
      msb_numbers = []

      case args[:search_engine]
      when :technet
        print_verbose("Searching advisories that include #{args[:keyword]} via Technet")
        msb_numbers = technet_search(args[:keyword])
      when :google
        print_verbose("Searching advisories that include #{args[:keyword]} via Google")
        msb_numbers = google_search(args[:keyword], args[:google_api_key], args[:google_search_engine_id])
      end

      msb_numbers
    end

    # Returns the download links for an advisory.
    #
    # @param msb [String]
    # @param regex [Regexp] Search filter
    # @return [Array]
    def collect_links_from_msb(msb, regex = nil)
      unless is_valid_msb?(msb)
        print_verbose_error "Not a valid MSB format: #{msb}"
        print_verbose_error 'Example of a correct one: ms15-100'
        return []
      end

      res = download_advisory(msb)

      if !has_advisory?(res)
        print_verbose_error "The advisory cannot be found for #{msb}"
        return []
      end

      links = get_details_aspx(res)
      if links.length == 0
        print_verbose_error "Unable to find download.microsoft.com links for #{msb}."
        return []
      else
        print_verbose("Found #{links.length} affected products for #{msb}.")
      end

      link_collector = []

      links.each do |link|
        download_page = get_download_page(link)
        download_links = get_download_links(download_page.body)
        if regex
          filtered_links = download_links.select { |l| Regexp.new(regex) === l }
          link_collector.concat(filtered_links)
        else
          link_collector.concat(download_links)
        end
      end

      link_collector
    end

    # Returns the download page.
    #
    # @param link [string]
    # @return [Net::Response]
    def get_download_page(link)
      res = send_http_get_request(link)

      if res.header['Location']
        return send_http_get_request("#{PatchFinder::Engine::MSU::MICROSOFT}/#{res.header['Location']}")
      end

      res
    end

    # Returns the MSB advisories found from Google.
    #
    # @param keyword [String]
    # @param api_key [String]
    # @param cx [String]
    # @return [Array]
    def google_search(keyword, api_key, cx)
      search = PatchFinder::Engine::MSU::Google.new(api_key: api_key, search_engine_id: cx)
      search.find_msb_numbers(keyword)
    end

    # Returns the MSB advisories found from Technet.
    #
    # @param keyword [String]
    # @return [Array]
    def technet_search(keyword)
      search = PatchFinder::Engine::MSU::Technet.new
      search.find_msb_numbers(keyword)
    end

    # Returns the advisory page.
    #
    # @param msb [String]
    # @return [String]
    def download_advisory(msb)
      send_http_get_request("#{PatchFinder::Engine::MSU::TECHNET}/en-us/library/security/#{msb}.aspx")
    end

    # Returns the found details pages
    #
    # @param res [Res::Response]
    # @return [Array]
    def get_details_aspx(res)
      links = []

      page = res.body
      n = ::Nokogiri::HTML(page)

      appropriate_pattern = get_appropriate_pattern(n)
      return links unless appropriate_pattern

      n.search(appropriate_pattern).each do |anchor|
        found_link = anchor.attributes['href'].value
        if /https:\/\/www\.microsoft\.com\/downloads\/details\.aspx\?familyid=/i === found_link
          begin
            links << found_link
          rescue ::URI::InvalidURIError
            print_verbose_error "Unable to parse URI: #{found_link}"
          end
        end
      end

      links
    end

    # Returns the downloads links
    #
    # @param page [String] HTML page
    # @return [Array]
    def get_download_links(page)
      page = ::Nokogiri::HTML(page)

      relative_uri = page.search('a').select { |a|
        a.attributes['href'] && a.attributes['href'].value.include?('confirmation.aspx?id=')
      }.first

      return [] unless relative_uri
      relative_uri = relative_uri.attributes['href'].value

      res = send_http_get_request("#{PatchFinder::Engine::MSU::MICROSOFT}/en-us/download/#{relative_uri}")
      n = ::Nokogiri::HTML(res.body)

      n.search('a').select { |a|
        a.attributes['href'] && a.attributes['href'].value.include?("#{PatchFinder::Engine::MSU::DOWNLOAD_MSFT}/download/")
      }.map! { |a| a.attributes['href'].value }.uniq
    end

    # Returns a pattern that matches the advisory page.
    #
    # @param n [Nokogiri::HTML::Document]
    # @return [String] If a match is found
    # @return [NilClass] If no match found
    def get_appropriate_pattern(n)
      PatchFinder::Engine::MSU::ADVISORY_PATTERNS.each do |pattern|
        if n.at_xpath(pattern[:check])
          return pattern[:pattern]
        end
      end

      nil
    end

    # Checks if the page is an advisory.
    #
    # @param res [Net::Response]
    # @return [Boolean]
    def has_advisory?(res)
      !res.body.include?('We are sorry. The page you requested cannot be found')
    end

    # Checks if the string is a MSB format.
    #
    # @param msb [String]
    # @return [Boolean]
    def is_valid_msb?(msb)
      /^ms\d\d\-\d\d\d$/i === msb
    end

  end
end
