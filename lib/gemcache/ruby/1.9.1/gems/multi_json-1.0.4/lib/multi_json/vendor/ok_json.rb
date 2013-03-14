# Copyright 2011 Keith Rarick
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# See https://github.com/kr/okjson for updates.

require 'stringio'

# Some parts adapted from
# http://golang.org/src/pkg/json/decode.go and
# http://golang.org/src/pkg/utf8/utf8.go
module MultiJson
  module OkJson
    extend self


    # Decodes a json document in string s and
    # returns the corresponding ruby value.
    # String s must be valid UTF-8. If you have
    # a string in some other encoding, convert
    # it first.
    #
    # String values in the resulting structure
    # will be UTF-8.
    def decode(s)
      ts = lex(s)
      v, ts = textparse(ts)
      if ts.length > 0
        raise Error, 'trailing garbage'
      end
      v
    end


    # Parses a "json text" in the sense of RFC 4627.
    # Returns the parsed value and any trailing tokens.
    # Note: this is almost the same as valparse,
    # except that it does not accept atomic values.
    def textparse(ts)
      if ts.length < 0
        raise Error, 'empty'
      end

      typ, _, val = ts[0]
      case typ
      when '{' then objparse(ts)
      when '[' then arrparse(ts)
      else
        raise Error, "unexpected #{val.inspect}"
      end
    end


    # Parses a "value" in the sense of RFC 4627.
    # Returns the parsed value and any trailing tokens.
    def valparse(ts)
      if ts.length < 0
        raise Error, 'empty'
      end

      typ, _, val = ts[0]
      case typ
      when '{' then objparse(ts)
      when '[' then arrparse(ts)
      when :val,:str then [val, ts[1..-1]]
      else
        raise Error, "unexpected #{val.inspect}"
      end
    end


    # Parses an "object" in the sense of RFC 4627.
    # Returns the parsed value and any trailing tokens.
    def objparse(ts)
      ts = eat('{', ts)
      obj = {}

      if ts[0][0] == '}'
        return obj, ts[1..-1]
      end

      k, v, ts = pairparse(ts)
      obj[k] = v

      if ts[0][0] == '}'
        return obj, ts[1..-1]
      end

      loop do
        ts = eat(',', ts)

        k, v, ts = pairparse(ts)
        obj[k] = v

        if ts[0][0] == '}'
          return obj, ts[1..-1]
        end
      end
    end


    # Parses a "member" in the sense of RFC 4627.
    # Returns the parsed values and any trailing tokens.
    def pairparse(ts)
      (typ, _, k), ts = ts[0], ts[1..-1]
      if typ != :str
        raise Error, "unexpected #{k.inspect}"
      end
      ts = eat(':', ts)
      v, ts = valparse(ts)
      [k, v, ts]
    end


    # Parses an "array" in the sense of RFC 4627.
    # Returns the parsed value and any trailing tokens.
    def arrparse(ts)
      ts = eat('[', ts)
      arr = []

      if ts[0][0] == ']'
        return arr, ts[1..-1]
      end

      v, ts = valparse(ts)
      arr << v

      if ts[0][0] == ']'
        return arr, ts[1..-1]
      end

      loop do
        ts = eat(',', ts)

        v, ts = valparse(ts)
        arr << v

        if ts[0][0] == ']'
          return arr, ts[1..-1]
        end
      end
    end


    def eat(typ, ts)
      if ts[0][0] != typ
        raise Error, "expected #{typ} (got #{ts[0].inspect})"
      end
      ts[1..-1]
    end


    # Sans s and returns a list of json tokens,
    # excluding white space (as defined in RFC 4627).
    def lex(s)
      ts = []
      while s.length > 0
        typ, lexeme, val = tok(s)
        if typ == nil
          raise Error, "invalid character at #{s[0,10].inspect}"
        end
        if typ != :space
          ts << [typ, lexeme, val]
        end
        s = s[lexeme.length..-1]
      end
      ts
    end


    # Scans the first token in s and
    # returns a 3-element list, or nil
    # if no such token exists.
    #
    # The first list element is one of
    # '{', '}', ':', ',', '[', ']',
    # :val, :str, and :space.
    #
    # The second element is the lexeme.
    #
    # The third element is the value of the
    # token for :val and :str, otherwise
    # it is the lexeme.
    def tok(s)
      case s[0]
      when ?{  then ['{', s[0,1], s[0,1]]
      when ?}  then ['}', s[0,1], s[0,1]]
      when ?:  then [':', s[0,1], s[0,1]]
      when ?,  then [',', s[0,1], s[0,1]]
      when ?[  then ['[', s[0,1], s[0,1]]
      when ?]  then [']', s[0,1], s[0,1]]
      when ?n  then nulltok(s)
      when ?t  then truetok(s)
      when ?f  then falsetok(s)
      when ?"  then strtok(s)
      when Spc then [:space, s[0,1], s[0,1]]
      when ?\t then [:space, s[0,1], s[0,1]]
      when ?\n then [:space, s[0,1], s[0,1]]
      when ?\r then [:space, s[0,1], s[0,1]]
      else          numtok(s)
      end
    end


    def nulltok(s);  s[0,4] == 'null'  && [:val, 'null',  nil]   end
    def truetok(s);  s[0,4] == 'true'  && [:val, 'true',  true]  end
    def falsetok(s); s[0,5] == 'false' && [:val, 'false', false] end


    def numtok(s)
      m = /-?([1-9][0-9]+|[0-9])([.][0-9]+)?([eE][+-]?[0-9]+)?/.match(s)
      if m && m.begin(0) == 0
        if m[3] && !m[2]
          [:val, m[0], Integer(m[1])*(10**Integer(m[3][1..-1]))]
        elsif m[2]
          [:val, m[0], Float(m[0])]
        else
          [:val, m[0], Integer(m[0])]
        end
      end
    end


    def strtok(s)
      m = /"([^"\\]|\\["\/\\bfnrt]|\\u[0-9a-fA-F]{4})*"/.match(s)
      if ! m
        raise Error, "invalid string literal at #{abbrev(s)}"
      end
      [:str, m[0], unquote(m[0])]
    end


    def abbrev(s)
      t = s[0,10]
      p = t['`']
      t = t[0,p] if p
      t = t + '...' if t.length < s.length
      '`' + t + '`'
    end


    # Converts a quoted json string literal q into a UTF-8-encoded string.
    # The rules are different than for Ruby, so we cannot use eval.
    # Unquote will raise an error if q contains control characters.
    def unquote(q)
      q = q[1...-1]
      a = q.dup # allocate a big enough string
      r, w = 0, 0
      while r < q.length
        c = q[r]
        case true
        when c == ?\\
          r += 1
          if r >= q.length
            raise Error, "string literal ends with a \"\\\": \"#{q}\""
          end

          case q[r]
          when ?",?\\,?/,?'
            a[w] = q[r]
            r += 1
            w += 1
          when ?b,?f,?n,?r,?t
            a[w] = Unesc[q[r]]
            r += 1
            w += 1
          when ?u
            r += 1
            uchar = begin
              hexdec4(q[r,4])
            rescue RuntimeError => e
              raise Error, "invalid escape sequence \\u#{q[r,4]}: #{e}"
            end
            r += 4
            if surrogate? uchar
              if q.length >= r+6
                uchar1 = hexdec4(q[r+2,4])
                uchar = subst(uchar, uchar1)
                if uchar != Ucharerr
                  # A valid pair; consume.
                  r += 6
                end
              end
            end
            w += ucharenc(a, w, uchar)
          else
            raise Error, "invalid escape char #{q[r]} in \"#{q}\""
          end
        when c == ?", c < Spc
          raise Error, "invalid character in string literal \"#{q}\""
        else
          # Copy anything else byte-for-byte.
          # Valid UTF-8 will remain valid UTF-8.
          # Invalid UTF-8 will remain invalid UTF-8.
          a[w] = c
          r += 1
          w += 1
        end
      end
      a[0,w]
    end


    # Encodes unicode character u as UTF-8
    # bytes in string a at position i.
    # Returns the number of bytes written.
    def ucharenc(a, i, u)
      case true
      when u <= Uchar1max
        a[i] = (u & 0xff).chr
        1
      when u <= Uchar2max
        a[i+0] = (Utag2 | ((u>>6)&0xff)).chr
        a[i+1] = (Utagx | (u&Umaskx)).chr
        2
      when u <= Uchar3max
        a[i+0] = (Utag3 | ((u>>12)&0xff)).chr
        a[i+1] = (Utagx | ((u>>6)&Umaskx)).chr
        a[i+2] = (Utagx | (u&Umaskx)).chr
        3
      else
        a[i+0] = (Utag4 | ((u>>18)&0xff)).chr
        a[i+1] = (Utagx | ((u>>12)&Umaskx)).chr
        a[i+2] = (Utagx | ((u>>6)&Umaskx)).chr
        a[i+3] = (Utagx | (u&Umaskx)).chr
        4
      end
    end


    def hexdec4(s)
      if s.length != 4
        raise Error, 'short'
      end
      (nibble(s[0])<<12) | (nibble(s[1])<<8) | (nibble(s[2])<<4) | nibble(s[3])
    end


    def subst(u1, u2)
      if Usurr1 <= u1 && u1 < Usurr2 && Usurr2 <= u2 && u2 < Usurr3
        return ((u1-Usurr1)<<10) | (u2-Usurr2) + Usurrself
      end
      return Ucharerr
    end


    def unsubst(u)
      if u < Usurrself || u > Umax || surrogate?(u)
        return Ucharerr, Ucharerr
      end
      u -= Usurrself
      [Usurr1 + ((u>>10)&0x3ff), Usurr2 + (u&0x3ff)]
    end


    def surrogate?(u)
      Usurr1 <= u && u < Usurr3
    end


    def nibble(c)
      case true
      when ?0 <= c && c <= ?9 then c.ord - ?0.ord
      when ?a <= c && c <= ?z then c.ord - ?a.ord + 10
      when ?A <= c && c <= ?Z then c.ord - ?A.ord + 10
      else
        raise Error, "invalid hex code #{c}"
      end
    end


    # Encodes x into a json text. It may contain only
    # Array, Hash, String, Numeric, true, false, nil.
    # (Note, this list excludes Symbol.)
    # X itself must be an Array or a Hash.
    # No other value can be encoded, and an error will
    # be raised if x contains any other value, such as
    # Nan, Infinity, Symbol, and Proc, or if a Hash key
    # is not a String.
    # Strings contained in x must be valid UTF-8.
    def encode(x)
      case x
      when Hash    then objenc(x)
      when Array   then arrenc(x)
      else
        raise Error, 'root value must be an Array or a Hash'
      end
    end


    def valenc(x)
      case x
      when Hash    then objenc(x)
      when Array   then arrenc(x)
      when String  then strenc(x)
      when Numeric then numenc(x)
      when true    then "true"
      when false   then "false"
      when nil     then "null"
      else
        if x.respond_to?(:to_json)
          x.to_json
        else
          raise Error, "cannot encode #{x.class}: #{x.inspect}"
        end
      end
    end


    def objenc(x)
      '{' + x.map{|k,v| keyenc(k) + ':' + valenc(v)}.join(',') + '}'
    end


    def arrenc(a)
      '[' + a.map{|x| valenc(x)}.join(',') + ']'
    end


    def keyenc(k)
      case k
      when String then strenc(k)
      else
        raise Error, "Hash key is not a string: #{k.inspect}"
      end
    end


    def strenc(s)
      t = StringIO.new
      t.putc(?")
      r = 0
      while r < s.length
        case s[r]
        when ?"  then t.print('\\"')
        when ?\\ then t.print('\\\\')
        when ?\b then t.print('\\b')
        when ?\f then t.print('\\f')
        when ?\n then t.print('\\n')
        when ?\r then t.print('\\r')
        when ?\t then t.print('\\t')
        else
          c = s[r]
          case true
          when Spc <= c && c <= ?~
            t.putc(c)
          when true
            u, size = uchardec(s, r)
            r += size - 1 # we add one more at the bottom of the loop
            if u < 0x10000
              t.print('\\u')
              hexenc4(t, u)
            else
              u1, u2 = unsubst(u)
              t.print('\\u')
              hexenc4(t, u1)
              t.print('\\u')
              hexenc4(t, u2)
            end
          else
            # invalid byte; skip it
          end
        end
        r += 1
      end
      t.putc(?")
      t.string
    end


    def hexenc4(t, u)
      t.putc(Hex[(u>>12)&0xf])
      t.putc(Hex[(u>>8)&0xf])
      t.putc(Hex[(u>>4)&0xf])
      t.putc(Hex[u&0xf])
    end


    def numenc(x)
      if x.nan? || x.infinite?
        return 'null'
      end rescue nil
      "#{x}"
    end


    # Decodes unicode character u from UTF-8
    # bytes in string s at position i.
    # Returns u and the number of bytes read.
    def uchardec(s, i)
      n = s.length - i
      return [Ucharerr, 1] if n < 1

      c0 = s[i].ord

      # 1-byte, 7-bit sequence?
      if c0 < Utagx
        return [c0, 1]
      end

      # unexpected continuation byte?
      return [Ucharerr, 1] if c0 < Utag2

      # need continuation byte
      return [Ucharerr, 1] if n < 2
      c1 = s[i+1].ord
      return [Ucharerr, 1] if c1 < Utagx || Utag2 <= c1

      # 2-byte, 11-bit sequence?
      if c0 < Utag3
        u = (c0&Umask2)<<6 | (c1&Umaskx)
        return [Ucharerr, 1] if u <= Uchar1max
        return [u, 2]
      end

      # need second continuation byte
      return [Ucharerr, 1] if n < 3
      c2 = s[i+2].ord
      return [Ucharerr, 1] if c2 < Utagx || Utag2 <= c2

      # 3-byte, 16-bit sequence?
      if c0 < Utag4
        u = (c0&Umask3)<<12 | (c1&Umaskx)<<6 | (c2&Umaskx)
        return [Ucharerr, 1] if u <= Uchar2max
        return [u, 3]
      end

      # need third continuation byte
      return [Ucharerr, 1] if n < 4
      c3 = s[i+3].ord
      return [Ucharerr, 1] if c3 < Utagx || Utag2 <= c3

      # 4-byte, 21-bit sequence?
      if c0 < Utag5
        u = (c0&Umask4)<<18 | (c1&Umaskx)<<12 | (c2&Umaskx)<<6 | (c3&Umaskx)
        return [Ucharerr, 1] if u <= Uchar3max
        return [u, 4]
      end

      return [Ucharerr, 1]
    end


    class Error < ::StandardError
    end


    Utagx = 0x80 # 1000 0000
    Utag2 = 0xc0 # 1100 0000
    Utag3 = 0xe0 # 1110 0000
    Utag4 = 0xf0 # 1111 0000
    Utag5 = 0xF8 # 1111 1000
    Umaskx = 0x3f # 0011 1111
    Umask2 = 0x1f # 0001 1111
    Umask3 = 0x0f # 0000 1111
    Umask4 = 0x07 # 0000 0111
    Uchar1max = (1<<7) - 1
    Uchar2max = (1<<11) - 1
    Uchar3max = (1<<16) - 1
    Ucharerr = 0xFFFD # unicode "replacement char"
    Usurrself = 0x10000
    Usurr1 = 0xd800
    Usurr2 = 0xdc00
    Usurr3 = 0xe000
    Umax = 0x10ffff

    Spc = ' '[0]
    Unesc = {?b=>?\b, ?f=>?\f, ?n=>?\n, ?r=>?\r, ?t=>?\t}
    Hex = '0123456789abcdef'
  end
end