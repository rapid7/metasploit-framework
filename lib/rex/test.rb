require 'test/unit'

# DEFAULTS
module Rex
class Test

$_REX_TEST_NO_MOCK = nil
$_REX_TEST_TIMEOUT = 30
$_REX_TEST_SMB_HOST = '10.4.10.58'
$_REX_TEXT_SMB_USER = 'SMBTest'
$_REX_TEXT_SMB_PASS = 'SMBTest'

# overwrite test defaults with rex/test-config.rb
def self.load()
    file = File.join( ENV.fetch('HOME'), '.msf3', 'test')
    begin
        if File.stat(file + '.rb')
            require file
        end
    rescue
        # just ignore the errors
    end

end

def self.cantmock()
    if (!$_REX_TEST_NO_MOCK)
        raise RuntimeError, "*** $_REX_TEST_NO_MOCK must not be set for this test ***", caller
    end
end

Rex::Test.load()

end
end