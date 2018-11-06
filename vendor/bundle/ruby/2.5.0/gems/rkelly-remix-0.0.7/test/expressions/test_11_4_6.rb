require File.dirname(__FILE__) + "/../helper"

class Expressions_11_4_6_Test < ECMAScriptTestCase
  @@tests = {
    :empty_string   => ["''", 0],
    :space_string   => ["' '", 0],
    :tab_string     => ["'\t'", 0],
    :newline_string => ["'\n'", 0],
    :cr_string      => ["'\r'", 0],
    :f_string       => ["'\f'", 0],
    :char_code_09   => ['String.fromCharCode(0x0009)', 0],
    :char_code_20   => ['String.fromCharCode(0x0020)', 0],
    :char_code_0C   => ['String.fromCharCode(0x000C)', 0],
    :char_code_0B   => ['String.fromCharCode(0x000B)', 0],
    :char_code_0A   => ['String.fromCharCode(0x000A)', 0],
    :lh_space_add   => ["'   ' + 999", 999],
    :lh_newline_add => ["'\n' + 999", 999],
    :lh_cr_add      => ["'\r' + 999", 999],
    :lh_tab_add     => ["'\t' + 999", 999],
    :lh_tab_f       => ["'\f' + 999", 999],
    :rh_space_add   => ["999 + '   '", 999],
    :rh_newline_add => ["999 + '\n'", 999],
    :rh_cr_add      => ["999 + '\r'", 999],
    :rh_tab_add     => ["999 + '\t'", 999],
    :rh_tab_f       => ["999 + '\f'", 999],
    :bs_space_add   => ["'   ' + 999 + '   '", 999],
    :bs_newline_add => ["'\n' + 999 + '\n'", 999],
    :bs_cr_add      => ["'\r' + 999 + '\r'", 999],
    :bs_tab_add     => ["'\t' + 999 + '\t'", 999],
    :bs_tab_f       => ["'\f' + 999 + '\f'", 999],
    :cl_09          => ["String.fromCharCode(0x0009) + 99", 99],
    :cl_20          => ["String.fromCharCode(0x0020) + 99", 99],
    :cl_0C          => ["String.fromCharCode(0x000C) + 99", 99],
    :cl_0B          => ["String.fromCharCode(0x000B) + 99", 99],
    :cl_0A          => ["String.fromCharCode(0x000A) + 99", 99],
    :cr_09          => ["99 + String.fromCharCode(0x0009)", 99],
    :cr_20          => ["99 + String.fromCharCode(0x0020)", 99],
    :cr_0C          => ["99 + String.fromCharCode(0x000C)", 99],
    :cr_0B          => ["99 + String.fromCharCode(0x000B)", 99],
    :cr_0A          => ["99 + String.fromCharCode(0x000A)", 99],
    :bs_09          => ["String.fromCharCode(0x0009) + 99 + String.fromCharCode(0x0009)", 99],
    :bs_20          => ["String.fromCharCode(0x0020) + 99 + String.fromCharCode(0x0020)", 99],
    :bs_0C          => ["String.fromCharCode(0x000C) + 99 + String.fromCharCode(0x000C)", 99],
    :bs_0B          => ["String.fromCharCode(0x000B) + 99 + String.fromCharCode(0x000B)", 99],
    :bs_0A          => ["String.fromCharCode(0x000A) + 99 + String.fromCharCode(0x000A)", 99],
    :infinity       => ["'Infinity'", 'Number.POSITIVE_INFINITY'],
    :neg_infinity   => ["'-Infinity'", 'Number.NEGATIVE_INFINITY'],
    :pos_infinity   => ["'+Infinity'", 'Number.POSITIVE_INFINITY'],
  }
  @@sign_tests = [
    [3.14159, 3.14159],
    ['3.', 3],
    ['3.e1', 30],
    ['3.e+1', 30],
    ['3.e-1', 0.30],
    ['.00001', 0.00001],
    ['.01e2', 1],
    ['.01e+2', 1],
    ['.01e-2', 0.0001],
    ['1234e5', 123400000],
    ['1234e+5', 123400000],
    ['1234e-5', 0.01234],
  ]
  0.upto(9) { |x| @@sign_tests << [x, x] }

  # 0x0 needs special treatment as sprintf("%#x", 0) results in "0"
  @@sign_tests << ["0x0", 0]
  @@sign_tests << ["0X0", 0]

  1.upto(15) { |x|
    @@sign_tests << [sprintf("%#x", x), x]
    @@sign_tests << [sprintf("%#x", x).gsub(/x/, 'X'), x]
    if sprintf("%#x", x) =~ /[a-f]/
      @@sign_tests << [sprintf("%#x", x).gsub(/([a-f])/) { |m| m.upcase }, x]
      @@sign_tests << [sprintf("%#x", x).upcase, x]
    end
  }

  @@sign_tests.each { |actual, expected|
    define_method(:"test_num_#{actual.to_s.gsub(/[\.+]/, '_')}") do
      @runtime.execute("
                       assert_equal(#{expected},  +('#{actual}'));
                       assert_equal(#{expected},  +('+#{actual}'));
                       assert_equal(-#{expected}, +('-#{actual}'));
                       ")
    end
  }

  @@tests.each do |name,(actual, expected)|
    define_method(:"test_#{name}") do
      @runtime.execute("assert_equal(#{expected}, +(#{actual}));")
    end
  end
end
