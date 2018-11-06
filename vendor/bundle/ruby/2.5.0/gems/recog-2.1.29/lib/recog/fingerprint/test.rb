
class Recog::Fingerprint::Test
  attr_accessor :content
  attr_accessor :attributes
  def initialize(content, attributes=[])
    @attributes = attributes

    if @attributes['_encoding'] && @attributes['_encoding'] == 'base64'
      @content = content.to_s.unpack('m*').first
    else
      @content = content
    end
  end

  def to_s
    content
  end
end
