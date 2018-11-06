module Nexpose
  module Sanitize
    def replace_entities(str)
      str.to_s.gsub(/&/, '&amp;').gsub(/'/, '&apos;').gsub(/"/, '&quot;').gsub(/</, '&lt;').gsub(/>/, '&gt;')
    end
  end

  module XMLUtils
    def parse_xml(xml)
      ::REXML::Document.new(xml.to_s)
    end

    def make_xml(name, opts = {}, data = '', append_session_id = true)
      xml = REXML::Element.new(name)
      if @session_id && append_session_id
        xml.attributes['session-id'] = @session_id
      end

      opts.keys.each do |k|
        xml.attributes[k] = "#{opts[k]}" unless opts[k].nil?
      end

      xml.text = data

      xml
    end

    # Check a typical Nexpose XML response for success.
    # Typically, the root element has a 'success' attribute, and its value is
    # '1' if the call succeeded.
    #
    def self.success?(xml_string)
      xml     = ::REXML::Document.new(xml_string.to_s)
      success = ::REXML::XPath.first(xml, '//@success')
      !success.nil? && success.value.to_i == 1
    end
  end

  # Function module for dealing with String to HostName|IPRange conversions.
  #
  module HostOrIP
    module_function

    # Convert a host or IP address to the corresponding HostName or IPRange
    # class.
    #
    # If the String cannot be converted, it will raise an error.
    #
    # @param [String] asset String representation of an IP or host name.
    # @return [IPRange|HostName] Valid class, if it can be converted.
    #
    def convert(asset)
      ips = asset.split('-').map(&:strip)
      IPAddr.new(ips[0])
      IPAddr.new(ips[1]) if ips[1]
      IPRange.new(ips[0], ips[1])
    rescue ArgumentError => e
      if e.message == 'invalid address'
        HostName.new(asset)
      else
        raise "Unable to parse asset: '#{asset}'. #{e.message}"
      end
    end

    # Parse a REXML::Document or REXML::Element for any hosts listed and convert
    # them to HostName and IPRange objects.
    #
    # @param [REXML::Document|REXML::Element] xml REXML class potentially
    #   containing host references.
    # @return [Array[HostName|IPRange]] Collection of parsed hosts.
    #
    def parse(xml)
      coll = []
      xml.elements.each('//range') do |elem|
        to = elem.attribute('to').nil? ? nil : elem.attribute('to').value
        coll << IPRange.new(elem.attribute('from').value, to)
      end
      xml.elements.each('//host') do |elem|
        coll << HostName.new(elem.text)
      end
      coll
    end
  end

  # Function module for converting to ISO 8601 and UTC dates expected by 2.0 API.
  module ISO8601
    module_function

    # Convert a string representation into a Time object.
    #
    # @param [String] time_string String representation in basic format.
    #   For example: '20141210T165822.412Z'
    # @return [Time] Time, if it can be converted.
    #
    def to_time(time_string)
      Time.strptime(time_string.to_s, '%Y%m%dT%H%M%S.%L%Z')
    end

    # Convert a time object into a UTC ISO 8601 basic date-time format.
    #
    # @param [Time|Date|DateTime] time Time to convert.
    # @return [String] ISO 8601 basic representation.
    #
    def to_string(time = Time.now)
      time.to_time.utc.strftime('%Y%m%dT%H%M%S.%LZ')
    end
  end

  # Functions for handling attributes as understood by the API.
  # In particular, the API expects a JSON object with the hash defined as:
  #  { "key": "key-string",
  #    "value": "value-string" }
  #
  module Attributes
    module_function

    # Convert an array of attributes into a hash consumable by the API.
    #
    # @param [Array[Hash]] arr Array of attributes to convert.
    # @return [Array[Hash]] Array formatted as expected by the API.
    #
    def to_hash(arr)
      arr.map(&:flatten).map { |p| { 'key' => p.first.to_s, 'value' => p.last.to_s } }
    end
  end
end
