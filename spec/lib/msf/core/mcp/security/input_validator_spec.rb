# frozen_string_literal: true

require 'msf/core/mcp'

RSpec.describe Msf::MCP::Security::InputValidator do
  describe '.validate_parameter!' do
    context 'with Array constraint (enum)' do
      it 'accepts value in the list' do
        expect(described_class.validate_parameter!('color', 'red', %w[red green blue])).to be true
      end

      it 'rejects value not in the list' do
        expect {
          described_class.validate_parameter!('color', 'yellow', %w[red green blue])
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Invalid color: "yellow". Must be one of: red, green, blue')
      end

      it 'includes the parameter name in error' do
        expect {
          described_class.validate_parameter!('fruit', 'pear', %w[apple banana])
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Invalid fruit: "pear". Must be one of: apple, banana')
      end
    end

    context 'with Range constraint' do
      it 'accepts value within range' do
        expect(described_class.validate_parameter!('port', 80, 1..65535)).to be true
      end

      it 'accepts boundary values' do
        expect(described_class.validate_parameter!('port', 1, 1..65535)).to be true
        expect(described_class.validate_parameter!('port', 65535, 1..65535)).to be true
      end

      it 'rejects value outside range' do
        expect {
          described_class.validate_parameter!('port', 0, 1..65535)
        }.to raise_error(Msf::MCP::Security::ValidationError, 'port must be between 1 and 65535: 0')
      end

      it 'rejects non-integer value' do
        expect {
          described_class.validate_parameter!('port', 'abc', 1..65535)
        }.to raise_error(Msf::MCP::Security::ValidationError, 'port must be an integer: "abc"')
      end

      it 'rejects nil value' do
        expect {
          described_class.validate_parameter!('port', nil, 1..65535)
        }.to raise_error(Msf::MCP::Security::ValidationError, 'port cannot be nil')
      end

      it 'raises ArgumentError for non-integer range' do
        expect {
          described_class.validate_parameter!('x', 1, 'a'..'z')
        }.to raise_error(ArgumentError, 'Range constraint must be a range of integers, got String..String')
      end

      context 'with Range value (range-in-range)' do
        it 'accepts range within constraint' do
          expect(described_class.validate_parameter!('ports', 80..443, 1..65535)).to be true
        end

        it 'accepts range matching constraint bounds' do
          expect(described_class.validate_parameter!('ports', 1..65535, 1..65535)).to be true
        end

        it 'rejects range starting below constraint' do
          expect {
            described_class.validate_parameter!('ports', 0..443, 1..65535)
          }.to raise_error(Msf::MCP::Security::ValidationError, 'ports must be between 1 and 65535: 0..443')
        end

        it 'rejects range ending above constraint' do
          expect {
            described_class.validate_parameter!('ports', 80..70000, 1..65535)
          }.to raise_error(Msf::MCP::Security::ValidationError, 'ports must be between 1 and 65535: 80..70000')
        end

        it 'rejects backwards range' do
          expect {
            described_class.validate_parameter!('ports', 443..80, 1..65535)
          }.to raise_error(Msf::MCP::Security::ValidationError, 'ports must be between 1 and 65535: 443..80')
        end

        it 'rejects range with non-integer bounds' do
          expect {
            described_class.validate_parameter!('ports', 'a'..'z', 1..65535)
          }.to raise_error(Msf::MCP::Security::ValidationError, 'ports must have integer bounds: "a".."z"')
        end
      end
    end

    context 'with Regexp constraint' do
      it 'accepts matching value' do
        expect(described_class.validate_parameter!('name', 'abc_123', /\A\w+\z/)).to be true
      end

      it 'rejects non-matching value' do
        expect {
          described_class.validate_parameter!('name', 'has spaces', /\A\w+\z/)
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Invalid name format: has spaces')
      end

      it 'does not raise error for an integer value when max_size is set' do
        expect(described_class.validate_parameter!('name', 33, /\A\w+\z/, max_size: 10)).to be true
      end
    end

    context 'with allow_nil option' do
      it 'allows nil when allow_nil is true' do
        expect(described_class.validate_parameter!('proto', nil, %w[tcp udp], allow_nil: true)).to be true
      end

      it 'allows empty string when allow_nil is true' do
        expect(described_class.validate_parameter!('proto', '', %w[tcp udp], allow_nil: true)).to be true
      end

      it 'rejects nil when allow_nil is false' do
        expect {
          described_class.validate_parameter!('proto', nil, %w[tcp udp])
        }.to raise_error(Msf::MCP::Security::ValidationError, 'proto cannot be nil')
      end

      it 'still validates non-nil values when allow_nil is true' do
        expect {
          described_class.validate_parameter!('proto', 'icmp', %w[tcp udp], allow_nil: true)
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Invalid proto: "icmp". Must be one of: tcp, udp')
      end
    end

    context 'with unsupported constraint type' do
      it 'raises ArgumentError' do
        expect {
          described_class.validate_parameter!('x', 'y', 42)
        }.to raise_error(ArgumentError, 'Unsupported constraint type: Integer')
      end
    end
  end

  describe '.validate_ip_address!' do
    context 'with valid IP addresses' do
      it 'accepts valid IPv4 address' do
        expect(described_class.validate_ip_address!('192.168.1.1')).to be true
      end

      it 'accepts valid IPv6 address' do
        expect(described_class.validate_ip_address!('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).to be true
      end

      it 'accepts valid CIDR notation' do
        expect(described_class.validate_ip_address!('192.168.1.0/24')).to be true
      end

      it 'accepts localhost' do
        expect(described_class.validate_ip_address!('127.0.0.1')).to be true
      end
    end

    context 'with invalid IP addresses' do
      it 'rejects malformed IPv4' do
        ['256.1.1.1', '192.168.1', '192.168.1.1.1', 'a.b.c.d'].each do |addr|
          expect {
            described_class.validate_ip_address!(addr)
          }.to raise_error(Msf::MCP::Security::ValidationError, "Invalid IP address or CIDR: #{addr}")
        end
      end

      it 'rejects out of range octets' do
        expect {
          described_class.validate_ip_address!('192.168.300.1')
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Invalid IP address or CIDR: 192.168.300.1')
      end

      it 'rejects invalid CIDR' do
        ['192.168.1.0/33', '192.168.1.0/-1', '192.168.1.0/abc'].each do |addr|
          expect {
            described_class.validate_ip_address!(addr)
          }.to raise_error(Msf::MCP::Security::ValidationError, "Invalid IP address or CIDR: #{addr}")
        end
      end

      it 'rejects random strings' do
        ['notanip', 'test.example.com', '192.168.one.two'].each do |addr|
          expect {
            described_class.validate_ip_address!(addr)
          }.to raise_error(Msf::MCP::Security::ValidationError, "Invalid IP address or CIDR: #{addr}")
        end
      end
    end

    context 'with empty or nil values' do
      it 'accepts nil' do
        expect(described_class.validate_ip_address!(nil)).to be true
      end

      it 'accepts empty string' do
        expect(described_class.validate_ip_address!('')).to be true
      end
    end
  end

  describe '.validate_port_range!' do
    context 'with valid single ports' do
      it 'accepts port 1' do
        expect(described_class.validate_port_range!(1)).to be true
      end

      it 'accepts port 65535' do
        expect(described_class.validate_port_range!(65535)).to be true
      end

      it 'accepts port 80' do
        expect(described_class.validate_port_range!(80)).to be true
      end
    end

    context 'with valid port ranges' do
      it 'accepts string range' do
        expect(described_class.validate_port_range!('1-1024')).to be true
      end

      it 'accepts range with max ports' do
        expect(described_class.validate_port_range!('1-65535')).to be true
      end
    end

    context 'with invalid ports' do
      it 'rejects port 0' do
        expect {
          described_class.validate_port_range!(0)
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Port must be between 1 and 65535: 0')
      end

      it 'rejects port above 65535' do
        expect {
          described_class.validate_port_range!(65536)
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Port must be between 1 and 65535: 65536')
      end

      it 'rejects negative ports' do
        expect {
          described_class.validate_port_range!(-1)
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Port must be between 1 and 65535: -1')
      end
    end

    context 'with invalid range formats' do
      it 'rejects backwards range' do
        expect {
          described_class.validate_port_range!('100-50')
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Port range must be between 1 and 65535: 100..50')
      end

      it 'rejects "1-"' do
        expect {
          described_class.validate_port_range!('1-')
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Port must be an integer: "1-"')
      end

      it 'rejects "-100"' do
        expect {
          described_class.validate_port_range!('-100')
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Port must be between 1 and 65535: -100')
      end

      it 'rejects "abc-def"' do
        expect {
          described_class.validate_port_range!('abc-def')
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Port range must have integer bounds: abc-def')
      end
    end

    context 'with empty or nil values' do
      it 'accepts nil' do
        expect(described_class.validate_port_range!(nil)).to be true
      end

      it 'accepts empty string' do
        expect(described_class.validate_port_range!('')).to be true
      end
    end
  end

  describe '.validate_only_up!' do
    context 'with valid boolean values' do
      it 'accepts true' do
        expect(described_class.validate_only_up!(true)).to be true
      end

      it 'accepts false' do
        expect(described_class.validate_only_up!(false)).to be true
      end
    end

    context 'with invalid values' do
      it 'rejects string "true"' do
        expect {
          described_class.validate_only_up!('true')
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Invalid only_up: "true". Must be one of: true, false')
      end

      it 'rejects string "false"' do
        expect {
          described_class.validate_only_up!('false')
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Invalid only_up: "false". Must be one of: true, false')
      end

      it 'rejects nil' do
        expect {
          described_class.validate_only_up!(nil)
        }.to raise_error(Msf::MCP::Security::ValidationError, 'only_up cannot be nil')
      end

      it 'rejects integer 1' do
        expect {
          described_class.validate_only_up!(1)
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Invalid only_up: 1. Must be one of: true, false')
      end

      it 'rejects integer 0' do
        expect {
          described_class.validate_only_up!(0)
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Invalid only_up: 0. Must be one of: true, false')
      end
    end
  end

  describe '.validate_protocol!' do
    context 'with valid protocols' do
      it 'accepts tcp' do
        expect(described_class.validate_protocol!('tcp')).to be true
      end

      it 'accepts udp' do
        expect(described_class.validate_protocol!('udp')).to be true
      end

      it 'accepts TCP (uppercase)' do
        expect(described_class.validate_protocol!('TCP')).to be true
      end

      it 'accepts UDP (uppercase)' do
        expect(described_class.validate_protocol!('UDP')).to be true
      end

      it 'accepts nil' do
        expect(described_class.validate_protocol!(nil)).to be true
      end

      it 'accepts empty string' do
        expect(described_class.validate_protocol!('')).to be true
      end
    end

    context 'with invalid protocols' do
      it 'rejects icmp' do
        expect {
          described_class.validate_protocol!('icmp')
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Invalid Protocol: "icmp". Must be one of: tcp, udp')
      end

      it 'rejects http' do
        expect {
          described_class.validate_protocol!('http')
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Invalid Protocol: "http". Must be one of: tcp, udp')
      end

      it 'rejects random string' do
        expect {
          described_class.validate_protocol!('invalid')
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Invalid Protocol: "invalid". Must be one of: tcp, udp')
      end
    end
  end

  describe '.validate_search_query!' do
    context 'with valid search queries' do
      it 'accepts normal search terms' do
        expect(described_class.validate_search_query!('apache')).to be true
      end

      it 'accepts search with spaces' do
        expect(described_class.validate_search_query!('apache http')).to be true
      end

      it 'accepts search with hyphens' do
        expect(described_class.validate_search_query!('ms17-010')).to be true
      end
    end

    context 'with invalid search queries' do
      it 'rejects empty string' do
        expect {
          described_class.validate_search_query!('')
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Search query cannot be empty')
      end

      it 'rejects nil' do
        expect {
          described_class.validate_search_query!(nil)
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Search query cannot be nil')
      end

      it 'rejects very long queries' do
        long_query = 'a' * 501
        expect {
          described_class.validate_search_query!(long_query)
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Search query too long (max 500 characters)')
      end

      it 'rejects non printable characters' do
        expect {
          described_class.validate_search_query!("bad\x15\x10")
        }.to raise_error(Msf::MCP::Security::ValidationError, /^Invalid Search query format:/)
      end
    end
  end

  describe '.validate_limit!' do
    it 'accepts valid limit' do
      expect(described_class.validate_limit!(100)).to be true
    end

    it 'accepts minimum limit' do
      expect(described_class.validate_limit!(1)).to be true
    end

    it 'rejects zero' do
      expect {
        described_class.validate_limit!(0)
      }.to raise_error(Msf::MCP::Security::ValidationError, 'Limit must be between 1 and 1000: 0')
    end

    it 'rejects negative number' do
      expect {
        described_class.validate_limit!(-10)
      }.to raise_error(Msf::MCP::Security::ValidationError, 'Limit must be between 1 and 1000: -10')
    end

    it 'rejects excessive limit' do
      expect {
        described_class.validate_limit!(10001)
      }.to raise_error(Msf::MCP::Security::ValidationError, 'Limit must be between 1 and 1000: 10001')
    end

    it 'accepts nil' do
      expect(described_class.validate_limit!(nil)).to be true
    end

    it 'accepts empty string' do
      expect(described_class.validate_limit!('')).to be true
    end
  end

  describe '.validate_offset!' do
    it 'accepts valid offset' do
      expect(described_class.validate_offset!(100)).to be true
    end

    it 'accepts zero offset' do
      expect(described_class.validate_offset!(0)).to be true
    end

    it 'rejects negative offset' do
      expect {
        described_class.validate_offset!(-10)
      }.to raise_error(Msf::MCP::Security::ValidationError, 'Offset must be between 0 and 1000: -10')
    end

    it 'rejects non-integer offset' do
      expect {
        described_class.validate_offset!('abc')
      }.to raise_error(Msf::MCP::Security::ValidationError, 'Offset must be an integer: "abc"')
    end

    it 'rejects excessive offset' do
      expect {
        described_class.validate_offset!(10001)
      }.to raise_error(Msf::MCP::Security::ValidationError, 'Offset must be between 0 and 1000: 10001')
    end
  end

  describe '.validate_pagination!' do
    context 'with valid pagination parameters' do
      it 'accepts valid limit and offset' do
        expect { described_class.validate_pagination!(100, 50) }.not_to raise_error
      end

      it 'accepts nil limit and offset' do
        expect { described_class.validate_pagination!(nil, nil) }.not_to raise_error
      end

      it 'accepts valid limit with nil offset' do
        expect { described_class.validate_pagination!(50, nil) }.not_to raise_error
      end

      it 'accepts nil limit with valid offset' do
        expect { described_class.validate_pagination!(nil, 0) }.not_to raise_error
      end
    end

    context 'with invalid pagination parameters' do
      it 'rejects invalid limit' do
        expect {
          described_class.validate_pagination!(0, 10)
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Limit must be between 1 and 1000: 0')
      end

      it 'rejects invalid offset' do
        expect {
          described_class.validate_pagination!(10, -5)
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Offset must be between 0 and 1000: -5')
      end

      it 'rejects both invalid parameters' do
        expect {
          described_class.validate_pagination!(0, -5)
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Limit must be between 1 and 1000: 0')
      end
    end
  end

  describe '.validate_module_type!' do
    context 'with valid module types' do
      it 'accepts exploit' do
        expect(described_class.validate_module_type!('exploit')).to be true
      end

      it 'accepts auxiliary' do
        expect(described_class.validate_module_type!('auxiliary')).to be true
      end

      it 'accepts post' do
        expect(described_class.validate_module_type!('post')).to be true
      end

      it 'accepts payload' do
        expect(described_class.validate_module_type!('payload')).to be true
      end

      it 'accepts encoder' do
        expect(described_class.validate_module_type!('encoder')).to be true
      end

      it 'accepts evasion' do
        expect(described_class.validate_module_type!('evasion')).to be true
      end

      it 'accepts nop' do
        expect(described_class.validate_module_type!('nop')).to be true
      end
    end

    context 'with invalid module types' do
      it 'rejects invalid type' do
        expect {
          described_class.validate_module_type!('invalid')
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Invalid Module type: "invalid". Must be one of: exploit, auxiliary, post, payload, encoder, evasion, nop')
      end

      it 'rejects uppercase type' do
        expect {
          described_class.validate_module_type!('EXPLOIT')
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Invalid Module type: "EXPLOIT". Must be one of: exploit, auxiliary, post, payload, encoder, evasion, nop')
      end

      it 'rejects empty string' do
        expect {
          described_class.validate_module_type!('')
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Module type cannot be empty')
      end

      it 'rejects nil' do
        expect {
          described_class.validate_module_type!(nil)
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Module type cannot be nil')
      end

      it 'rejects scanner (not a valid type)' do
        expect {
          described_class.validate_module_type!('scanner')
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Invalid Module type: "scanner". Must be one of: exploit, auxiliary, post, payload, encoder, evasion, nop')
      end
    end
  end

  describe '.validate_module_name!' do
    context 'with valid module names' do
      it 'accepts simple module name' do
        expect(described_class.validate_module_name!('apache_exploit')).to be true
      end

      it 'accepts module name with path' do
        expect(described_class.validate_module_name!('exploit/windows/smb/ms17_010_eternalblue')).to be true
      end

      it 'accepts module name with hyphens' do
        expect(described_class.validate_module_name!('exploit/windows/ms17-010')).to be true
      end

      it 'accepts module name with underscores' do
        expect(described_class.validate_module_name!('auxiliary/scanner/http/wordpress_scanner')).to be true
      end

      it 'accepts module name with numbers' do
        expect(described_class.validate_module_name!('exploit/multi/http/struts2_rest_xstream')).to be true
      end
    end

    context 'with invalid module names' do
      it 'rejects empty string' do
        expect {
          described_class.validate_module_name!('')
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Module name cannot be empty')
      end

      it 'rejects nil' do
        expect {
          described_class.validate_module_name!(nil)
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Module name cannot be nil')
      end

      it 'rejects whitespace-only string' do
        expect {
          described_class.validate_module_name!('   ')
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Invalid Module name format:    ')
      end

      it 'rejects very long module names' do
        long_name = 'a' * 501
        expect {
          described_class.validate_module_name!(long_name)
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Module name too long (max 500 characters)')
      end

      it 'rejects module name with spaces' do
        expect {
          described_class.validate_module_name!('exploit/windows/my exploit')
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Invalid Module name format: exploit/windows/my exploit')
      end

      it 'rejects module name with special characters' do
        expect {
          described_class.validate_module_name!('exploit/windows/test@exploit')
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Invalid Module name format: exploit/windows/test@exploit')
      end

      it 'rejects module name with dots' do
        expect {
          described_class.validate_module_name!('exploit/windows/../etc/passwd')
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Invalid Module name format: exploit/windows/../etc/passwd')
      end

      it 'rejects module name with backslashes' do
        expect {
          described_class.validate_module_name!('exploit\\windows\\test')
        }.to raise_error(Msf::MCP::Security::ValidationError, 'Invalid Module name format: exploit\windows\test')
      end
    end
  end

  describe 'fuzzing tests' do
    it 'handles random IP-like strings' do
      1000.times do
        random_ip = "#{rand(300)}.#{rand(300)}.#{rand(300)}.#{rand(300)}"
        begin
          described_class.validate_ip_address!(random_ip)
        rescue Msf::MCP::Security::ValidationError
          # Expected for invalid IPs
        end
      end
    end

    it 'handles random port numbers' do
      1000.times do
        random_port = rand(-100..70000)
        begin
          described_class.validate_port_range!(random_port)
        rescue Msf::MCP::Security::ValidationError
          # Expected for invalid ports
        end
      end
    end

    it 'handles random strings with special characters' do
      special_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '[', ']', '{', '}', '|', '\\', '/', '<', '>']
      100.times do
        random_string = Array.new(rand(1..50)) { special_chars.sample }.join
        begin
          described_class.validate_search_query!(random_string)
        rescue Msf::MCP::Security::ValidationError
          # Expected for invalid queries
        end
      end
    end
  end
end
