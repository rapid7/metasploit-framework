# -*- coding: binary -*-
module Rex
module MIME
# Set of helpers methods to deal with SMTP encoding related topics.
module Encoding

  # Enforces CRLF on the input data
  #
  # @param data [String] The data to CRLF enforce.
  # @return [String] CRLF enforced data.
  def force_crlf(data)
    data.gsub("\r", '').gsub("\n", "\r\n")
  end

end
end
end
