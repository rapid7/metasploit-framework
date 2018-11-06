require 'json'
require 'patch_finder/core/helper'
require_relative 'constants'

module PatchFinder
  module Engine
    module MSU

      class GoogleClientException < RuntimeError ; end

      class Google

        include Helper

        GOOGLEAPIS = 'https://www.googleapis.com'

        attr_reader :api_key
        attr_reader :search_engine_id

        # API Doc:
        # https://developers.google.com/custom-search/json-api/v1/using_rest
        # Known bug:
        # * Always gets 20 MSB results. Weird.

        # Initializes the Google API client.
        #
        # @param opts [Hash]
        # @option opts [String] :api_key Google API key.
        # @option opts [String] :search_engine_id Google Search engine ID.
        def initialize(opts = {})
          @api_key = opts[:api_key]
          @search_engine_id = opts[:search_engine_id]
        end

        # Returns the MSB (advisories) numbers for a search keyword.
        #
        # @param keyword [String]
        # @return [Array]
        def find_msb_numbers(keyword)
          msb_numbers = []
          next_starting_index = 1
          search_opts = {
            keyword: keyword,
            starting_index: next_starting_index
          }

          begin
            while
              results = search(search_opts)
              items = results['items']
              items.each do |item|
                title = item['title']
                msb = title.scan(/Microsoft Security Bulletin (MS\d\d\-\d\d\d)/).flatten.first
                msb_numbers << msb.downcase if msb
              end

              next_starting_index = get_next_index(results)
              next_page = results['queries']['nextPage']

              # Google API Documentation:
              # https://developers.google.com/custom-search/json-api/v1/using_rest
              # "This role is not present if the current results are the last page.
              # Note: This API returns up to the first 100 results only."
              break if next_page.nil? || next_starting_index > 100
            end
          rescue GoogleClientException => e
            print_verbose_error(e.message)
            return msb_numbers.uniq
          end

          msb_numbers.uniq
        end

        # Searches the Google API.
        #
        # @param opts [Hash]
        # @option opts [Fixnum] :starting_index
        # @option opts [String] :keyword
        # @return [Hash] JSON
        def search(opts = {})
          starting_index = opts[:starting_index]

          search_string = URI.escape([
            opts[:keyword],
            'intitle:"Microsoft Security Bulletin"',
            '-"Microsoft Security Bulletin Summary"'
          ].join(' '))

          req_str = "#{GOOGLEAPIS}/customsearch/v1?"
          req_str << "key=#{api_key}&"
          req_str << "cx=#{search_engine_id}&"
          req_str << "q=#{search_string}&"
          req_str << "start=#{starting_index.to_s}&"
          req_str << 'num=10&'
          req_str << 'c2coff=1'

          res = send_http_get_request(req_str)
          results = parse_results(res)
          if starting_index == 1
            print_verbose("Number of search results: #{get_total_results(results)}")
          end

          results
        end

        # Returns the string data to JSON.
        #
        # @raise [GoogleClientException] The Google Search API returns an error.
        # @param res [Net::HTTPResponse]
        def parse_results(res)
          j = JSON.parse(res.body)

          if j['error']
            message = j['error']['errors'].first['message']
            reason  = j['error']['errors'].first['reason']
            fail GoogleClientException, "Google Search failed. #{message} (#{reason})"
          end

          j
        end

        # Returns totalResults
        #
        # @param j [Hash] JSON response.
        # @return [Fixnum]
        def get_total_results(j)
          j['queries']['request'].first['totalResults'].to_i
        end

        # Returns startIndex
        #
        # @param j [Hash] JSON response.
        # @return [Fixnum]
        def get_next_index(j)
          j['queries']['nextPage'] ? j['queries']['nextPage'].first['startIndex'] : 0
        end

      end
    end
  end
end
