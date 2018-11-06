module Dnsruby
class MessageEncoder #:nodoc: all
  def initialize
    @data = ''
    @names = {}
    yield self if block_given?
  end

  def to_s
    @data
  end

  def put_bytes(d)
    @data << d
  end

  def put_pack(template, *d)
    begin
      @data << d.pack(template)
    rescue Encoding::CompatibilityError => e
      raise Dnsruby::EncodeError.new("IDN support currently requires punycode string")
    end
  end

  def put_length16
    length_index = @data.length
    @data << "\0\0"
    data_start = @data.length
    yield
    data_end = @data.length
    @data[length_index, 2] = [data_end - data_start].pack("n")
  end

  def put_string(d)
    begin
      self.put_pack("C", d.length)
      @data << d
    rescue Encoding::CompatibilityError => e
      raise Dnsruby::EncodeError.new("IDN support currently requires punycode string")
    end
  end

  def put_string_list(ds)
    ds.each { |d| self.put_string(d) }
  end

  def put_rr(rr, canonical=false)
    #  RFC4034 Section 6.2
    put_name(rr.name, canonical)
    put_pack('nnN', rr.type.code, rr.klass.code, rr.ttl)
    put_length16 { rr.encode_rdata(self, canonical) }
  end

  def put_name(d, canonical = false, downcase = canonical)
    #  DNSSEC requires some records (e.g. NSEC, RRSIG) to be canonicalised, but
    #  not downcased. YUK!
    d = d.downcase if downcase
    put_labels(d.to_a, canonical)
  end

  def put_labels(d, do_canonical)
    d.each_index do |i|
      domain = d[i..-1].join('.')
      if !do_canonical && (idx = @names[domain])
        self.put_pack('n', 0xc000 | idx)
        return
      else
        @names[domain] = @data.length
        self.put_label(d[i])
      end
    end
    @data << "\0"
  end


  def put_label(d)
    #       s, = Name.encode(d)
    s = d
    raise RuntimeError, "length of #{s} is #{s.string.length} (larger than 63 octets)" if s.string.length > 63
    self.put_string(s.string)
  end
end
end