module Msf
  module Handler
    module ReverseHttp
      module UriChecksum

        #
        # Define 8-bit checksums for matching URLs
        # These are based on charset frequency
        #
        URI_CHECKSUM_INITW = 92
        URI_CHECKSUM_INITJ = 88
        URI_CHECKSUM_CONN  = 98

        #
        # Precalculated checkums as fallback
        #
        URI_CHECKSUM_PRECALC = [
            "Zjjaq", "pIlfv", "UvoxP", "sqnx9", "zvoVO", "Pajqy", "7ziuw", "vecYp", "yfHsn", "YLzzp",
            "cEzvr", "abmri", "9tvwr", "vTarp", "ocrgc", "mZcyl", "xfcje", "nihqa", "40F17", "zzTWt",
            "E3192", "wygVh", "pbqij", "rxdVs", "ajtsf", "wvuOh", "hwRwr", "pUots", "rvzoK", "vUwby",
            "tLzyk", "zxbuV", "niaoy", "ukxtU", "vznoU", "zuxyC", "ymvag", "Jxtxw", "404KC", "DE563",
            "0A7G9", "yorYv", "zzuqP", "czhwo", "949N8", "a1560", "5A2S3", "Q652A", "KR201", "uixtg",
            "U0K02", "4EO56", "H88H4", "5M8E6", "zudkx", "ywlsh", "luqmy", "09S4I", "L0GG0", "V916E",
            "KFI11", "A4BN8", "C3E2Q", "UN804", "E75HG", "622eB", "1OZ71", "kynyx", "0RE7F", "F8CR2",
            "1Q2EM", "txzjw", "5KD1S", "GLR40", "11BbD", "MR8B2", "X4V55", "W994P", "13d2T", "6J4AZ",
            "HD2EM", "766bL", "8S4MF", "MBX39", "UJI57", "eIA51", "9CZN2", "WH6AA", "a6BF9", "8B1Gg",
            "J2N6Z", "144Kw", "7E37v", "9I7RR", "PE6MF", "K0c4M", "LR3IF", "38p3S", "39ab3", "O0dO1",
            "k8H8A", "0Fz3B", "o1PE1", "h7OI0", "C1COb", "bMC6A", "8fU4C", "3IMSO", "8DbFH", "2YfG5",
            "bEQ1E", "MU6NI", "UCENE", "WBc0E", "T1ATX", "tBL0A", "UGPV2", "j3CLI", "7FXp1", "yN07I",
            "YE6k9", "KTMHE", "a7VBJ", "0Uq3R", "70Ebn", "H2PqB", "83edJ", "0w5q2", "72djI", "wA5CQ",
            "KF0Ix", "i7AZH", "M9tU5", "Hs3RE", "F9m1i", "7ecBF", "zS31W", "lUe21", "IvCS5", "j97nC",
            "CNtR5", "1g8gV", "7KwNG", "DB7hj", "ORFr7", "GCnUD", "K58jp", "5lKo8", "GPIdP", "oMIFJ",
            "2xYb1", "LQQPY", "FGQlN", "l5COf", "dA3Tn", "v9RWC", "VuAGI", "3vIr9", "aO3zA", "CIfx5",
            "Gk6Uc", "pxL94", "rKYJB", "TXAFp", "XEOGq", "aBOiJ", "qp6EJ", "YGbq4", "dR8Rh", "g0SVi",
            "iMr6L", "HMaIl", "yOY1Z", "UXr5Y", "PJdz6", "OQdt7", "EmZ1s", "aLIVe", "cIeo2", "mTTNP",
            "eVKy5", "hf5Co", "gFHzG", "VhTWN", "DvAWf", "RgFJp", "MoaXE", "Mrq4W", "hRQAp", "hAzYA",
            "oOSWV", "UKMme", "oP0Zw", "Mxd6b", "RsRCh", "dlk7Q", "YU6zf", "VPDjq", "ygERO", "dZZcL",
            "dq5qM", "LITku", "AZIxn", "bVwPL", "jGvZK", "XayKP", "rTYVY", "Vo2ph", "dwJYR", "rLTlS",
            "BmsfJ", "Dyv1o", "j9Hvs", "w0wVa", "iDnBy", "uKEgk", "uosI8", "2yjuO", "HiOue", "qYi4t",
            "7nalj", "ENekz", "rxca0", "rrePF", "cXmtD", "Xlr2y", "S7uxk", "wJqaP", "KmYyZ", "cPryG",
            "kYcwH", "FtDut", "xm1em", "IaymY", "fr6ew", "ixDSs", "YigPs", "PqwBs", "y2rkf", "vwaTM",
            "aq7wp", "fzc4z", "AyzmQ", "epJbr", "culLd", "CVtnz", "tPjPx", "nfry8", "Nkpif", "8kuzg",
            "zXvz8", "oVQly", "1vpnw", "jqaYh", "2tztj", "4tslx"
        ]

        # Map "random" URIs to static strings, allowing us to randomize
        # the URI sent in the first request.
        # @param uri_match [String] The URI string to convert back to the original static value
        # @return [String] The static URI value derived from the checksum
        def process_uri_resource(uri_match)

          # This allows 'random' strings to be used as markers for
          # the INIT and CONN request types, based on a checksum
          uri_strip, uri_conn = uri_match.split('_', 2)
          uri_strip.sub!(/^\//, '')
          uri_check = Rex::Text.checksum8(uri_strip)

          # Match specific checksums and map them to static URIs
          case uri_check
            when URI_CHECKSUM_INITW
              uri_match = "/INITM"
            when URI_CHECKSUM_INITJ
              uri_match = "/INITJM"
            when URI_CHECKSUM_CONN
              uri_match = "/CONN_" + ( uri_conn || Rex::Text.rand_text_alphanumeric(16) )
          end

          uri_match
        end

        # Create a URI that matches a given checksum
        # @param sum [Fixnum] The checksum value you are trying to create a URI for
        # @return [String] The URI string that checksums to the given value
        def generate_uri_checksum(sum)
          chk = ("a".."z").to_a + ("A".."Z").to_a + ("0".."9").to_a
          32.times do
            uri = Rex::Text.rand_text_alphanumeric(3)
            chk.sort_by {rand}.each do |x|
              return(uri + x) if Rex::Text.checksum8(uri + x) == sum
            end
          end

          # Otherwise return one of the pre-calculated strings
          return URI_CHECKSUM_PRECALC[sum]
        end

      end
    end
  end
end
