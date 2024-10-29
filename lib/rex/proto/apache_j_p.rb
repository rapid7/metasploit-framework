# -*- coding: binary -*-

require 'bindata'

# @see: https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html
module Rex::Proto::ApacheJP
  class ApacheJPBoolean < BinData::Primitive
    endian  :big

    uint8   :data

    def get
      self.data != 0
    end

    def set(v)
      self.data = v ? 1 : 0
    end
  end

  class ApacheJPString < BinData::Primitive
    endian  :big

    uint16  :len, value: -> { data.length }
    stringz :data

    def get
      self.data
    end

    def set(v)
      self.data = v
    end
  end

  class ApacheJPHeaderName < BinData::Primitive
    COMMON_HEADERS = []

    endian :big

    uint16  :len_or_code
    stringz :data, onlyif: -> { len_or_code < 0xa000 }

    def get
      if len_or_code >= 0xa000
        self.class::COMMON_HEADERS[(len_or_code.to_i & 0xff) - 1]
      else
        self.data
      end
    end

    def set(v)
      if (idx = self.class::COMMON_HEADERS.index(v))
        self.len_or_code = 0xa000 | (idx + 1)
      else
        raise RuntimeError if v.length >= 0xa000

        self.len_or_code = v.length
        self.data = v
      end
    end
  end

  class ApacheJPReqHeaderName < ApacheJPHeaderName
    COMMON_HEADERS = %w{ accept accept-charset accept-encoding accept-language authorization connection content-type content-length cookie cookie2 host pragma referer user-agent }
  end

  class ApacheJPResHeaderName < ApacheJPHeaderName
    COMMON_HEADERS = %w{ Content-Type Content-Language Content-Length Date Last-Modified Location Set-Cookie Set-Cookie2 Servlet-Engine Status WWW-Authentication }
  end

  class ApacheJPRequestHeader < BinData::Record
    endian :big

    apache_jp_req_header_name :header_name
    apache_jp_string          :header_value
  end

  class ApacheJPResponseHeader < BinData::Record
    endian :big

    apache_jp_res_header_name :header_name
    apache_jp_string          :header_value
  end

  class ApacheJPRequestAttribute < BinData::Record
    CODE_CONTEXT = 1
    CODE_SERVLET_PATH = 2
    CODE_REMOTE_USER = 3
    CODE_AUTH_TYPE = 4
    CODE_QUERY_STRING = 5
    CODE_JVM_ROUTE = 6
    CODE_SSL_CERT = 7
    CODE_SSL_CIPHER = 8
    CODE_SSL_SESSION = 9
    CODE_REQ_ATTRIBUTE = 10
    CODE_TERMINATOR = 0xff

    endian :big

    uint8            :code
    apache_jp_string :attribute_name, onlyif: -> { code == CODE_REQ_ATTRIBUTE }
    apache_jp_string :attribute_value, onlyif: -> { code != CODE_TERMINATOR }
  end

  class ApacheJPForwardRequest < BinData::Record
    HTTP_METHOD_OPTIONS = 1
    HTTP_METHOD_GET = 2
    HTTP_METHOD_HEAD = 3
    HTTP_METHOD_POST = 4
    HTTP_METHOD_PUT = 5
    HTTP_METHOD_DELETE = 6
    HTTP_METHOD_TRACE = 7
    HTTP_METHOD_PROPFIND = 8
    HTTP_METHOD_PROPPATCH = 9
    HTTP_METHOD_MKCOL = 10
    HTTP_METHOD_COPY = 11
    HTTP_METHOD_MOVE = 12
    HTTP_METHOD_LOCK = 13
    HTTP_METHOD_UNLOCK = 14
    HTTP_METHOD_ACL = 15
    HTTP_METHOD_REPORT = 16
    HTTP_METHOD_VERSION_CONTROL = 17
    HTTP_METHOD_CHECKIN = 18
    HTTP_METHOD_CHECKOUT = 19
    HTTP_METHOD_UNCHECKOUT = 20
    HTTP_METHOD_SEARCH = 21
    PREFIX_CODE = 2

    endian :big

    uint8             :prefix_code, value: PREFIX_CODE
    uint8             :http_method
    apache_jp_string  :protocol, initial_value: 'HTTP/1.1'
    apache_jp_string  :req_uri
    apache_jp_string  :remote_addr
    apache_jp_string  :remote_host
    apache_jp_string  :server_name
    uint16            :server_port, initial_value: -> { is_ssl ? 80 : 443 }
    apache_jp_boolean :is_ssl, initial_value: false
    uint16            :num_headers, initial_value: -> { headers.length }
    array             :headers, type: :apache_jp_request_header, initial_length: :num_headers
    array             :attributes, type: :apache_jp_request_attribute, read_until: -> { element.code == ApacheJPRequestAttribute::TERMINATOR }
  end

  class ApacheJPSendBodyChunk < BinData::Record
    PREFIX_CODE = 3

    endian :big

    uint8   :prefix_code, value: PREFIX_CODE
    uint16  :body_chunk_length, initial_value: -> { body_chunk.length }
    string  :body_chunk, read_length: :body_chunk_length
  end

  class ApacheJPSendHeaders < BinData::Record
    PREFIX_CODE = 4

    endian :big

    uint8             :prefix_code, value: PREFIX_CODE
    uint16            :http_status_code
    apache_jp_string  :http_status_msg
    uint16            :num_headers, initial_value: -> { header.length }
    array             :headers, type: :apache_jp_response_header, initial_length: :num_headers
  end

  class ApacheJPEndResponse < BinData::Record
    PREFIX_CODE = 5

    endian :big

    uint8              :prefix_code, value: PREFIX_CODE
    apache_jp_boolean  :reuse
  end

  class ApacheJPGetBodyChunk < BinData::Record
    PREFIX_CODE = 6

    endian :big

    uint8   :prefix_code, value: PREFIX_CODE
    uint16  :requested_length
  end
end
