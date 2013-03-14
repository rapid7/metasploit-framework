$LOAD_PATH.unshift("#{File.dirname(__FILE__)}/../lib") if __FILE__ == $0

require 'mime/types'
require 'minitest/autorun'

class TestMIME_Type < MiniTest::Unit::TestCase
  def yaml_mime_type_from_array
    MIME::Type.from_array('text/x-yaml', %w(yaml yml), '8bit', 'd9d172f608')
  end

  def setup
    @zip = MIME::Type.new('x-appl/x-zip') { |t| t.extensions = ['zip', 'zp'] }
  end

  def test_class_from_array
    yaml = yaml_mime_type_from_array
    assert_instance_of(MIME::Type, yaml)
    assert_equal('text/yaml', yaml.simplified)
  end

  def test_class_from_hash
    yaml = MIME::Type.from_hash('Content-Type' => 'text/x-yaml',
                                'Content-Transfer-Encoding' => '8bit',
                                'System' => 'd9d172f608',
                                'Extensions' => %w(yaml yml))
    assert_instance_of(MIME::Type, yaml)
    assert_equal('text/yaml', yaml.simplified)
  end

  def test_class_from_mime_type
    zip2 = MIME::Type.from_mime_type(@zip)
    assert_instance_of(MIME::Type, @zip)
    assert_equal('appl/zip', @zip.simplified)
    refute_equal(@zip.object_id, zip2.object_id)
  end

  def test_class_simplified
    assert_equal(MIME::Type.simplified('text/plain'), 'text/plain')
    assert_equal(MIME::Type.simplified('image/jpeg'), 'image/jpeg')
    assert_equal(MIME::Type.simplified('application/x-msword'), 'application/msword')
    assert_equal(MIME::Type.simplified('text/vCard'), 'text/vcard')
    assert_equal(MIME::Type.simplified('application/pkcs7-mime'), 'application/pkcs7-mime')
    assert_equal(@zip.simplified, 'appl/zip')
    assert_equal(MIME::Type.simplified('x-xyz/abc'), 'xyz/abc')
  end

  def test_CMP # '<=>'
    assert(MIME::Type.new('text/plain') == MIME::Type.new('text/plain'))
    assert(MIME::Type.new('text/plain') != MIME::Type.new('image/jpeg'))
    assert(MIME::Type.new('text/plain') == 'text/plain')
    assert(MIME::Type.new('text/plain') != 'image/jpeg')
    assert(MIME::Type.new('text/plain') > MIME::Type.new('text/html'))
    assert(MIME::Type.new('text/plain') > 'text/html')
    assert(MIME::Type.new('text/html') < MIME::Type.new('text/plain'))
    assert(MIME::Type.new('text/html') < 'text/plain')
    assert('text/html' == MIME::Type.new('text/html'))
    assert('text/html' < MIME::Type.new('text/plain'))
    assert('text/plain' > MIME::Type.new('text/html'))
  end

  def test_ascii_eh
    assert(MIME::Type.new('text/plain').ascii?)
    refute(MIME::Type.new('image/jpeg').ascii?)
    refute(MIME::Type.new('application/x-msword').ascii?)
    assert(MIME::Type.new('text/vCard').ascii?)
    refute(MIME::Type.new('application/pkcs7-mime').ascii?)
    refute(@zip.ascii?)
  end

  def test_binary_eh
    refute(MIME::Type.new('text/plain').binary?)
    assert(MIME::Type.new('image/jpeg').binary?)
    assert(MIME::Type.new('application/x-msword').binary?)
    refute(MIME::Type.new('text/vCard').binary?)
    assert(MIME::Type.new('application/pkcs7-mime').binary?)
    assert(@zip.binary?)
  end

  def test_complete_eh
    yaml = yaml_mime_type_from_array
    assert(yaml.complete?)
    yaml.extensions = nil
    refute(yaml.complete?)
  end

  def test_content_type
    assert_equal(MIME::Type.new('text/plain').content_type, 'text/plain')
    assert_equal(MIME::Type.new('image/jpeg').content_type, 'image/jpeg')
    assert_equal(MIME::Type.new('application/x-msword').content_type, 'application/x-msword')
    assert_equal(MIME::Type.new('text/vCard').content_type, 'text/vCard')
    assert_equal(MIME::Type.new('application/pkcs7-mime').content_type, 'application/pkcs7-mime')
    assert_equal(@zip.content_type, 'x-appl/x-zip');
  end

  def test_encoding
    assert_equal(MIME::Type.new('text/plain').encoding, 'quoted-printable')
    assert_equal(MIME::Type.new('image/jpeg').encoding, 'base64')
    assert_equal(MIME::Type.new('application/x-msword').encoding, 'base64')
    assert_equal(MIME::Type.new('text/vCard').encoding, 'quoted-printable')
    assert_equal(MIME::Type.new('application/pkcs7-mime').encoding, 'base64')

    yaml = yaml_mime_type_from_array
    assert_equal(yaml.encoding, '8bit')
    yaml.encoding = 'base64'
    assert_equal(yaml.encoding, 'base64')
    yaml.encoding = :default
    assert_equal(yaml.encoding, 'quoted-printable')
    assert_raises(ArgumentError) { yaml.encoding = 'binary' }
    assert_equal(@zip.encoding, 'base64')
  end

  def _test_default_encoding
    raise NotImplementedError, 'Need to write test_default_encoding'
  end

  def _test_docs
    raise NotImplementedError, 'Need to write test_docs'
  end

  def _test_docs_equals
    raise NotImplementedError, 'Need to write test_docs_equals'
  end

  def test_eql?
    assert(MIME::Type.new('text/plain').eql?(MIME::Type.new('text/plain')))
    refute(MIME::Type.new('text/plain').eql?(MIME::Type.new('image/jpeg')))
    refute(MIME::Type.new('text/plain').eql?('text/plain'))
    refute(MIME::Type.new('text/plain').eql?('image/jpeg'))
  end

  def _test_encoding
    raise NotImplementedError, 'Need to write test_encoding'
  end

  def _test_encoding_equals
    raise NotImplementedError, 'Need to write test_encoding_equals'
  end

  def test_extensions
    yaml = yaml_mime_type_from_array
    assert_equal(yaml.extensions, %w(yaml yml))
    yaml.extensions = 'yaml'
    assert_equal(yaml.extensions, ['yaml'])
    assert_equal(@zip.extensions.size, 2)
    assert_equal(@zip.extensions, ['zip', 'zp'])
  end

  def _test_extensions_equals
    raise NotImplementedError, 'Need to write test_extensions_equals'
  end

  def test_like_eh
    assert(MIME::Type.new('text/plain').like?(MIME::Type.new('text/plain')))
    assert(MIME::Type.new('text/plain').like?(MIME::Type.new('text/x-plain')))
    refute(MIME::Type.new('text/plain').like?(MIME::Type.new('image/jpeg')))
    assert(MIME::Type.new('text/plain').like?('text/plain'))
    assert(MIME::Type.new('text/plain').like?('text/x-plain'))
    refute(MIME::Type.new('text/plain').like?('image/jpeg'))
  end

  def test_media_type
    assert_equal(MIME::Type.new('text/plain').media_type, 'text')
    assert_equal(MIME::Type.new('image/jpeg').media_type, 'image')
    assert_equal(MIME::Type.new('application/x-msword').media_type, 'application')
    assert_equal(MIME::Type.new('text/vCard').media_type, 'text')
    assert_equal(MIME::Type.new('application/pkcs7-mime').media_type, 'application')
    assert_equal(MIME::Type.new('x-chemical/x-pdb').media_type, 'chemical')
    assert_equal(@zip.media_type, 'appl')
  end

  def _test_obsolete_eh
    raise NotImplementedError, 'Need to write test_obsolete_eh'
  end

  def _test_obsolete_equals
    raise NotImplementedError, 'Need to write test_obsolete_equals'
  end

  def test_platform_eh
    yaml = yaml_mime_type_from_array
    refute(yaml.platform?)
    yaml.system = nil
    refute(yaml.platform?)
    yaml.system = %r{#{RUBY_PLATFORM}}
    assert(yaml.platform?)
  end

  def test_raw_media_type
    assert_equal(MIME::Type.new('text/plain').raw_media_type, 'text')
    assert_equal(MIME::Type.new('image/jpeg').raw_media_type, 'image')
    assert_equal(MIME::Type.new('application/x-msword').raw_media_type, 'application')
    assert_equal(MIME::Type.new('text/vCard').raw_media_type, 'text')
    assert_equal(MIME::Type.new('application/pkcs7-mime').raw_media_type, 'application')

    assert_equal(MIME::Type.new('x-chemical/x-pdb').raw_media_type, 'x-chemical')
    assert_equal(@zip.raw_media_type, 'x-appl')
  end

  def test_raw_sub_type
    assert_equal(MIME::Type.new('text/plain').raw_sub_type, 'plain')
    assert_equal(MIME::Type.new('image/jpeg').raw_sub_type, 'jpeg')
    assert_equal(MIME::Type.new('application/x-msword').raw_sub_type, 'x-msword')
    assert_equal(MIME::Type.new('text/vCard').raw_sub_type, 'vCard')
    assert_equal(MIME::Type.new('application/pkcs7-mime').raw_sub_type, 'pkcs7-mime')
    assert_equal(@zip.raw_sub_type, 'x-zip')
  end

  def test_registered_eh
    assert(MIME::Type.new('text/plain').registered?)
    assert(MIME::Type.new('image/jpeg').registered?)
    refute(MIME::Type.new('application/x-msword').registered?)
    assert(MIME::Type.new('text/vCard').registered?)
    assert(MIME::Type.new('application/pkcs7-mime').registered?)
    refute(@zip.registered?)
  end

  def _test_registered_equals
    raise NotImplementedError, 'Need to write test_registered_equals'
  end

  def test_signature_eh
    refute(MIME::Type.new('text/plain').signature?)
    refute(MIME::Type.new('image/jpeg').signature?)
    refute(MIME::Type.new('application/x-msword').signature?)
    assert(MIME::Type.new('text/vCard').signature?)
    assert(MIME::Type.new('application/pkcs7-mime').signature?)
  end

  def test_simplified
    assert_equal(MIME::Type.new('text/plain').simplified, 'text/plain')
    assert_equal(MIME::Type.new('image/jpeg').simplified, 'image/jpeg')
    assert_equal(MIME::Type.new('application/x-msword').simplified, 'application/msword')
    assert_equal(MIME::Type.new('text/vCard').simplified, 'text/vcard')
    assert_equal(MIME::Type.new('application/pkcs7-mime').simplified, 'application/pkcs7-mime')
    assert_equal(MIME::Type.new('x-chemical/x-pdb').simplified, 'chemical/pdb')
  end

  def test_sub_type
    assert_equal(MIME::Type.new('text/plain').sub_type, 'plain')
    assert_equal(MIME::Type.new('image/jpeg').sub_type, 'jpeg')
    assert_equal(MIME::Type.new('application/x-msword').sub_type, 'msword')
    assert_equal(MIME::Type.new('text/vCard').sub_type, 'vcard')
    assert_equal(MIME::Type.new('application/pkcs7-mime').sub_type, 'pkcs7-mime')
    assert_equal(@zip.sub_type, 'zip')
  end

  def test_system_equals
    yaml = yaml_mime_type_from_array
    assert_equal(yaml.system, %r{d9d172f608})
    yaml.system = /win32/
    assert_equal(yaml.system, %r{win32})
    yaml.system = nil
    assert_nil(yaml.system)
  end

  def test_system_eh
    yaml = yaml_mime_type_from_array
    assert(yaml.system?)
    yaml.system = nil
    refute(yaml.system?)
  end

  def test_to_a
    yaml = yaml_mime_type_from_array
    assert_equal(yaml.to_a, ['text/x-yaml', %w(yaml yml), '8bit',
                 /d9d172f608/, nil, nil, nil, false])
  end

  def test_to_hash
    yaml = yaml_mime_type_from_array
    assert_equal(yaml.to_hash,
                 { 'Content-Type' => 'text/x-yaml',
                    'Content-Transfer-Encoding' => '8bit',
                    'Extensions' => %w(yaml yml),
                    'System' => /d9d172f608/,
                    'Registered' => false,
                    'URL' => nil,
                    'Obsolete' => nil,
                    'Docs' => nil })
  end

  def test_to_s
    assert_equal("#{MIME::Type.new('text/plain')}", 'text/plain')
  end

  def test_class_constructors
    refute_nil(@zip)
    yaml = MIME::Type.new('text/x-yaml') do |y|
      y.extensions = %w(yaml yml)
      y.encoding = '8bit'
      y.system = 'd9d172f608'
    end
    assert_instance_of(MIME::Type, yaml)
    assert_raises(MIME::InvalidContentType) { MIME::Type.new('apps') }
    assert_raises(MIME::InvalidContentType) { MIME::Type.new(nil) }
  end

  def _test_to_str
    raise NotImplementedError, 'Need to write test_to_str'
  end

  def _test_url
    raise NotImplementedError, 'Need to write test_url'
  end

  def _test_url_equals
    raise NotImplementedError, 'Need to write test_url_equals'
  end

  def _test_urls
    raise NotImplementedError, 'Need to write test_urls'
  end

  def __test_use_instead
    raise NotImplementedError, 'Need to write test_use_instead'
  end
end
