module Nexpose

  # Data table functions which extract data from the Nexpose UI.
  #
  # The functions in this file are utility functions for accessing data in the
  # same manner as the Nexpose UI. These functions are not designed for external
  # use, but to aid exposing data through other methods in the gem.
  #
  module DataTable
    module_function

    # Helper method to get the YUI tables into a consumable Ruby object.
    #
    # @param [Connection] console API connection to a Nexpose console.
    # @param [String] address Controller address relative to https://host:port
    # @param [Hash] parameters Parameters that need to be sent to the controller
    #    The following attributes may need to be provided:
    #      'sort' Column to sort by
    #      'table-id' The ID of the table to get from this controller
    # @param [Fixnum] page_size Number of records to include per page.
    #   Value must conform to supported defaults: -1, 10, 25, 50, 100, 500.
    # @param [Fixnum] records number of records to return, gets all if not
    #   specified.
    # @param [Boolean] post Whether to use form post or get to retrieve data.
    # @return [Array[Hash]] An array of hashes representing the requested table.
    #
    # Example usage:
    #   DataTable._get_json_table(@console,
    #                             '/data/asset/site',
    #                             { 'sort' => 'assetName',
    #                               'table-id' => 'site-assets',
    #                               'siteID' => site_id })
    #
    def _get_json_table(console, address, parameters = {}, page_size = 500, records = nil, post = true)
      parameters['dir']        = 'DESC'
      parameters['startIndex'] = -1
      parameters['results']    = -1
      if post
        request = lambda { |p| AJAX.form_post(console, address, p) }
      else
        request = lambda { |p| AJAX.get(console, address.dup, AJAX::CONTENT_TYPE::JSON, p) }
      end

      response = request.call(parameters)
      data     = JSON.parse(response)
      # Don't attept to grab more records than there are.
      total = data['totalRecords']
      return [] if total.zero?
      total = records.nil? ? total : [records, total].min
      rows  = []
      parameters['results'] = page_size
      while rows.length < total
        parameters['startIndex'] = rows.length
        data = JSON.parse(request.call(parameters))
        rows.concat data['records']
      end
      rows
    end

    # Helper method to get a Dyntable into a consumable Ruby object.
    #
    # @param [Connection] console API connection to a Nexpose console.
    # @param [String] address Tag address with parameters relative to
    #    https://host:port
    # @return [Array[Hash]] array of hashes representing the requested table.
    #
    # Example usage:
    #   DataTable._get_dyn_table(@console, '/data/asset/os/dyntable.xml?tableID=OSSynopsisTable')
    #
    def _get_dyn_table(console, address, payload = nil)
      if payload
        response = AJAX.post(console, address, payload)
      else
        response = AJAX.get(console, address)
      end
      response = REXML::Document.new(response)

      headers = _dyn_headers(response)
      rows    = _dyn_rows(response)
      rows.map { |row| Hash[headers.zip(row)] }
    end

    # Parse headers out of a dyntable response.
    def _dyn_headers(response)
      headers = []
      response.elements.each('DynTable/MetaData/Column') do |header|
        headers << header.attributes['name']
      end
      headers
    end

    # Parse rows out of a dyntable into an array of values.
    def _dyn_rows(response)
      rows = []
      response.elements.each('DynTable/Data/tr') do |row|
        rows << _dyn_record(row)
      end
      rows
    end

    # Parse records out of the row of a dyntable.
    def _dyn_record(row)
      record = []
      row.elements.each('td') do |value|
        record << (value.text ? value.text.to_s : '')
      end
      record
    end
  end
end
