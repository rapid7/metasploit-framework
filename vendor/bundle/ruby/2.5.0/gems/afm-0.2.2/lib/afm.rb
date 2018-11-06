module AFM
  
  ISO_LATIN1_ENCODING = %w(
   .notdef .notdef .notdef .notdef .notdef .notdef .notdef .notdef
   .notdef .notdef .notdef .notdef .notdef .notdef .notdef .notdef
   .notdef .notdef .notdef .notdef .notdef .notdef .notdef .notdef
   .notdef .notdef .notdef .notdef .notdef .notdef .notdef .notdef space
   exclam quotedbl numbersign dollar percent ampersand quoteright
   parenleft parenright asterisk plus comma minus period slash zero one
   two three four five six seven eight nine colon semicolon less equal
   greater question at A B C D E F G H I J K L M N O P Q R S
   T U V W X Y Z bracketleft backslash bracketright asciicircum
   underscore quoteleft a b c d e f g h i j k l m n o p q r s
   t u v w x y z braceleft bar braceright asciitilde .notdef .notdef
   .notdef .notdef .notdef .notdef .notdef .notdef .notdef .notdef
   .notdef .notdef .notdef .notdef .notdef .notdef .notdef dotlessi grave
   acute circumflex tilde macron breve dotaccent dieresis .notdef ring
   cedilla .notdef hungarumlaut ogonek caron space exclamdown cent
   sterling currency yen brokenbar section dieresis copyright ordfeminine
   guillemotleft logicalnot hyphen registered macron degree plusminus
   twosuperior threesuperior acute mu paragraph periodcentered cedilla
   onesuperior ordmasculine guillemotright onequarter onehalf threequarters
   questiondown Agrave Aacute Acircumflex Atilde Adieresis Aring AE
   Ccedilla Egrave Eacute Ecircumflex Edieresis Igrave Iacute Icircumflex
   Idieresis Eth Ntilde Ograve Oacute Ocircumflex Otilde Odieresis
   multiply Oslash Ugrave Uacute Ucircumflex Udieresis Yacute Thorn
   germandbls agrave aacute acircumflex atilde adieresis aring ae
   ccedilla egrave eacute ecircumflex edieresis igrave iacute icircumflex
   idieresis eth ntilde ograve oacute ocircumflex otilde odieresis divide
   oslash ugrave uacute ucircumflex udieresis yacute thorn ydieresis
  )
  
  
  class Font
    attr_reader :metadata, :char_metrics, :char_metrics_by_code, :kern_pairs
    
    # Loading a Font Metrics file by absolute path (no automatic font path resolution)
    def initialize(filename)
      @metadata = {}
      @char_metrics = {}
      @char_metrics_by_code = {}
      @kern_pairs = []
      File.open(filename) do |file|
        mode = :meta
        file.each_line do |line|
          case(line)
          when /^StartFontMetrics/ ; mode = :meta
          when /^StartCharMetrics/ ; mode = :char_metrics
          when /^EndCharMetrics/ ; mode = :meta
          when /^StartKernData/ ; mode = :kern_data
          when /^StartKernPairs/ ; mode = :kern_pairs
          when /^EndKernPairs/ ; mode = :kern_data
          when /^EndKernData/ ; mode = :meta
          else
            case(mode)
            when :meta
              if match = line.match(/^([\w]+) (.*)$/)
                @metadata[match[1]] = match[2]
              end
            when :char_metrics
              metrics = {}
              metrics[:charcode] = match[1].to_i if match = line.match(/C (-?\d+) *?;/)
              metrics[:wx] = match[1].to_i if match = line.match(/WX (-?\d+) *?;/)
              metrics[:name] = match[1] if match = line.match(/N ([.\w]+) *?;/)
              if match = line.match(/B (-?\d+) (-?\d+) (-?\d+) (-?\d+) *?;/)
                metrics[:boundingbox] = [match[1].to_i, match[2].to_i, match[3].to_i, match[4].to_i] 
              end
              @char_metrics[metrics[:name]] = metrics if metrics[:name]
              @char_metrics_by_code[metrics[:charcode]] = metrics if metrics[:charcode] && metrics[:charcode] > 0
            when :kern_pairs
              if match = line.match(/^KPX ([.\w]+) ([.\w]+) (-?\d+)$/)
                @kern_pairs << [match[1], match[2], match[3].to_i]
              end
            end
          end
        end
      end
    end
    
    # 
    # alias for new()
    def self.from_file(file)
      self.new(file)
    end
    
    #
    # Get metadata by key
    def [](key)
      @metadata[key]
    end
    #
    # Get metrics for character. Takes an integer (charcode) or
    # a one-char string. currently works only for Latin1 strings,
    # since we only have a chartable for the Latin1 charset so far.
    # (shamelessly stolen from AFM.pm by Gisle Aas)
    def metrics_for(char)
      glyph = if (char.kind_of?(Integer))
        ISO_LATIN1_ENCODING[char]
      else
        ISO_LATIN1_ENCODING[char.unpack("C*").first]
      end
      @char_metrics[glyph]
    end
  end
end
