# -*- coding: binary -*-
module Rex
module Exploitation

#
# Encrypts javascript code
#
class EncryptJS
  #
  # Encrypts a javascript string.
  #
  # Encrypts a javascript string via XOR using a given key.
  # The key must be passed to the executed javascript
  # so that it can decrypt itself.
  # The provided loader gets the key from
  # "location.search.substring(1)"
  #
  # This should bypass any detection of the file itself
  # as information not part of the file is needed to
  # decrypt the original javascript code.
  #
  # Example:
  # <code>
  # js = <<ENDJS
  #     function say_hi() {
  #         var foo = "Hello, world";
  #         document.writeln(foo);
  #     }
  # ENDJS
  # key = 'secret'
  # js_encrypted = EncryptJS.encrypt(js, key)
  # </code>
  #
  # You might use something like this in exploit
  # modules to pass the key to the javascript
  # <code>
  # if (!request.uri.match(/\?\w+/))
  #	  send_local_redirect(cli, "?#{@key}")
  #	  return
  # end
  # </code>
  #

  def self.encrypt(js, key)
    js.gsub!(/[\r\n]/, '')

    encoded = Rex::Encoding::Xor::Generic.encode(js, key)[0].unpack("H*")[0]

    # obfuscate the eval call to circumvent generic detection
    eval = 'eval'.split(//).join(Rex::Text.rand_text_alpha(rand(5)).upcase)
    eval_call = 'window["' + eval + '".replace(/[A-Z]/g,"")]'

    js_loader = Rex::Exploitation::ObfuscateJS.new <<-ENDJS
    var exploit = '#{encoded}';
    var encoded = '';
    for (i = 0;i<exploit.length;i+=2) {
      encoded += String.fromCharCode(parseInt(exploit.substring(i, i+2), 16));
    }
    var pass = location.search.substring(1);
    var decoded = '';
    for (i=0;i<encoded.length;i++) {
      decoded += String.fromCharCode(encoded.charCodeAt(i) ^ pass.charCodeAt(i%pass.length));
    }
    #{eval_call}(decoded);
    ENDJS

    js_loader.obfuscate(
      'Symbols' => {
        'Variables' => [ 'exploit', 'encoded', 'pass', 'decoded' ],
      },
      'Strings' => false
    )
  end

end

end
end
