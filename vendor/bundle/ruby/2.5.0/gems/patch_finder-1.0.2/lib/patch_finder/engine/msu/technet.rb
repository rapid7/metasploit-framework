require 'json'
require 'nokogiri'
require 'patch_finder/core/helper'
require_relative 'constants'

module PatchFinder
  module Engine
    module MSU
      class Technet

        include Helper

        # Initializes the Technet client.
        #
        # @return [void]
        def initialize
          @firstpage ||= lambda {
            uri = '/en-us/security/bulletin/dn602597.aspx'
            res = send_http_get_request("#{TECHNET}#{uri}")
            return res.body
          }.call
        end

        # Returns the MSB (advisories) numbers for a search keyword.
        #
        # @param keyword [String]
        # @return [Array]
        def find_msb_numbers(keyword)
          product_list_matches = get_product_dropdown_list.select { |p| Regexp.new(keyword) === p[:option_text] }
          if product_list_matches.empty?
            print_verbose('No match from the product list, attempting a generic search')
            search_by_keyword(keyword)
          else
            product_names = []
            ids = []
            product_list_matches.each do |e|
              ids << e[:option_value]
              product_names << e[:option_text]
            end
            print_verbose("Matches from the product list (#{product_names.length}): #{ product_names * ', ' }")
            search_by_product_ids(ids)
          end
        end

        # Searches the Technet engine.
        #
        # @param keyword [String]
        # @return [Hash] JSON
        def search(keyword)
          req_str = "#{TECHNET}/security/bulletin/services/GetBulletins?"
          req_str << "searchText=#{keyword}&"
          req_str << 'sortField=0&'
          req_str << 'sortOrder=1&'
          req_str << 'currentPage=1&'
          req_str << 'bulletinsPerPage=9999&'
          req_str << 'locale=en-us'

          res = send_http_get_request(req_str)
          begin
            return JSON.parse(res.body)
          rescue JSON::ParserError
          end

          {}
        end

        # Searches for the MSBs (advisories) based on product IDs (as search keywords)
        #
        # @param ids [Array]
        # @return [Array]
        def search_by_product_ids(ids)
          msb_numbers = []

          ids.each do |id|
            j = search(id)
            msb = j['b'].collect { |e| e['Id'] }.map { |e| e.downcase }
            msb_numbers.concat(msb)
          end

          msb_numbers
        end

        # Searches for the MSBs (advisories) based on a keyword.
        #
        # @param keyword [String]
        # @return [Hash]
        def search_by_keyword(keyword)
          j = search(keyword)
          j['b'].collect { |e| e['Id'] }.map { |e| e.downcase }
        end

        # Returns the Technet product list.
        #
        # @return [Array]
        def get_product_dropdown_list
          @product_dropdown_list ||= lambda {
            list = []

            page = ::Nokogiri::HTML(firstpage)
            page.search('//div[@class="sb-search"]//select[@id="productDropdown"]//option').each do |product|
              option_value = product.attributes['value'].value
              option_text  = product.text
              next if option_value == '-1' # This is the ALL option
              list << { option_value: option_value, option_text: option_text }
            end

            list
          }.call
        end

        attr_reader :firstpage
      end
    end
  end
end
