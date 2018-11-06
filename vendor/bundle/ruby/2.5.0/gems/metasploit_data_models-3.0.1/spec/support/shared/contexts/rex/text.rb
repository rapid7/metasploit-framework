RSpec.shared_context 'Rex::Text' do
  before(:example) do
    rex_text = Module.new do
      def self.ascii_safe_hex(str, whitespace=false)
        if whitespace
          str.gsub(/([\x00-\x20\x80-\xFF])/n){ |x| "\\x%.2x" % x.unpack("C*")[0] }
        else
          str.gsub(/([\x00-\x08\x0b\x0c\x0e-\x1f\x80-\xFF])/n){ |x| "\\x%.2x" % x.unpack("C*")[0]}
        end
      end
    end

    stub_const('Rex::Text', rex_text)
  end
end