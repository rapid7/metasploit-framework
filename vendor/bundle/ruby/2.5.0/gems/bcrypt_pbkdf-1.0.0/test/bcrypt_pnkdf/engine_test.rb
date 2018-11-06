require 'minitest/autorun'
require 'test_helper'

# bcrypt_pbkdf in ruby using libsodium
require 'rbnacl/libsodium'
require 'rbnacl'
require 'rbnacl/hash'

BCRYPT_BLOCKS = 8
BCRYPT_HASHSIZE = BCRYPT_BLOCKS * 4

def bcrypt_pbkdf(password, salt, keylen, rounds)
  stride = (keylen + BCRYPT_HASHSIZE - 1) / BCRYPT_HASHSIZE
  amt = (keylen + stride - 1) / stride

  sha2pass = RbNaCl::Hash.sha512(password)
  #puts "[RB] sha2pass:#{sha2pass.inspect} #{sha2pass.size}"

  remlen = keylen

  countsalt = salt + "\x00"*4
  saltlen = salt.size

  key = "\x00"*keylen

  # generate key in BCRYPT_HASHSIZE pieces
  count = 1
  while remlen > 0
    countsalt[saltlen + 0] = ((count >> 24) & 0xff).chr
    countsalt[saltlen + 1] = ((count >> 16) & 0xff).chr
    countsalt[saltlen + 2] = ((count >> 8) & 0xff).chr
    countsalt[saltlen + 3] = (count & 0xff).chr
    #puts "[RC] countsalt: #{countsalt.inspect} len:#{countsalt.size}"

    sha2salt = RbNaCl::Hash.sha512(countsalt)
    tmpout = BCryptPbkdf::Engine::__bc_crypt_hash(sha2pass, sha2salt)
    out = tmpout.clone

    #puts "[RB] out: #{out.inspect} keylen:#{remlen} count:#{count}"
    (1...rounds).each do |i|
      sha2salt = RbNaCl::Hash.sha512(tmpout)
      tmpout = BCryptPbkdf::Engine::__bc_crypt_hash(sha2pass, sha2salt)
      out.bytes.each_with_index {|o,j| out.setbyte(j,o ^ tmpout[j].ord) }
    end

    amt = [amt, remlen].min
    (0...amt).each do |i|
      dest = i * stride + (count -1)
      key[dest] = out[i] if (dest < keylen)
    end
    
    remlen -= amt
    count += 1
  end
  key
end


class TestExt < MiniTest::Unit::TestCase
  def test_table
    assert_equal table, table.map{ |p,s,l,r| [p,s,l,r,BCryptPbkdf::Engine::__bc_crypt_pbkdf(p,s,l,r).bytes] }
  end
  def test_ruby_and_native_returns_the_same
    table.each do |p,s,l,r|
      assert_equal bcrypt_pbkdf(p,s,l,r), BCryptPbkdf::Engine::__bc_crypt_pbkdf(p,s,l,r)
      assert_equal bcrypt_pbkdf(p,s,l,r), BCryptPbkdf::key(p,s,l,r)
    end
  end
  

  def table
    [
      ["pass2", "salt2", 12, 2, [214, 14, 48, 162, 131, 206, 121, 176, 50, 104, 231, 252]], 
      ["\u0000\u0001foo", "\u0001\u0002fooo3", 14, 5, [46, 189, 32, 185, 94, 85, 232, 10, 84, 26, 44, 161, 49, 126]],
      ["doozoasd", "fooo$AS!", 14, 22, [57, 62, 50, 107, 70, 155, 65, 5, 129, 211, 189, 169, 188, 65]]
    ]
  end
end