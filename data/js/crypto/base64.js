// Base64 implementation stolen from http://www.webtoolkit.info/javascript-base64.html
// variable names changed to make obfuscation easier
var Base64 = {
  // private property
  _keyStr:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",

  // private method
  _utf8_encode : function ( input ){
    input = input.replace(/\\r\\n/g,"\\n");
    var utftext = "";
    var input_idx;

    for (input_idx = 0; input_idx < input.length; input_idx++) {
      var chr = input.charCodeAt(input_idx);
      if (chr < 128) {
        utftext += String.fromCharCode(chr);
      }
      else if((chr > 127) && (chr < 2048)) {
        utftext += String.fromCharCode((chr >> 6) | 192);
        utftext += String.fromCharCode((chr & 63) | 128);
      } else {
        utftext += String.fromCharCode((chr >> 12) | 224);
        utftext += String.fromCharCode(((chr >> 6) & 63) | 128);
        utftext += String.fromCharCode((chr & 63) | 128);
      }
    }

    return utftext;
  },

  // public method for encoding
  encode : function( input ) {
    var output = "";
    var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
    var input_idx = 0;

    input = Base64._utf8_encode(input);

    while (input_idx < input.length) {
      chr1 = input.charCodeAt( input_idx++ );
      chr2 = input.charCodeAt( input_idx++ );
      chr3 = input.charCodeAt( input_idx++ );

      enc1 = chr1 >> 2;
      enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
      enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
      enc4 = chr3 & 63;

      if (isNaN(chr2)) {
        enc3 = enc4 = 64;
      } else if (isNaN(chr3)) {
        enc4 = 64;
      }
      output = output +
      this._keyStr.charAt(enc1) + this._keyStr.charAt(enc2) +
      this._keyStr.charAt(enc3) + this._keyStr.charAt(enc4);
    }
    return output;
  },
  // public method for decoding
  decode : function (input) {
    var output = "";
    var chr1, chr2, chr3;
    var enc1, enc2, enc3, enc4;
    var i = 0;

    input = input.replace(/[^A-Za-z0-9\\+\\/\\=]/g, "");

    while (i < input.length) {

      enc1 = this._keyStr.indexOf(input.charAt(i++));
      enc2 = this._keyStr.indexOf(input.charAt(i++));
      enc3 = this._keyStr.indexOf(input.charAt(i++));
      enc4 = this._keyStr.indexOf(input.charAt(i++));

      chr1 = (enc1 << 2) | (enc2 >> 4);
      chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
      chr3 = ((enc3 & 3) << 6) | enc4;

      output = output + String.fromCharCode(chr1);

      if (enc3 != 64) {
        output = output + String.fromCharCode(chr2);
      }
      if (enc4 != 64) {
        output = output + String.fromCharCode(chr3);
      }

    }

    output = Base64._utf8_decode(output);

    return output;

  },
  _utf8_decode : function (utftext) {
    var string = "";
    var input_idx = 0;
    var chr1 = 0;
    var chr2 = 0;
    var chr3 = 0;

    while ( input_idx < utftext.length ) {

      chr1 = utftext.charCodeAt(input_idx);

      if (chr1 < 128) {
        string += String.fromCharCode(chr1);
        input_idx++;
      }
      else if((chr1 > 191) && (chr1 < 224)) {
        chr2 = utftext.charCodeAt(input_idx+1);
        string += String.fromCharCode(((chr1 & 31) << 6) | (chr2 & 63));
        input_idx += 2;
      } else {
        chr2 = utftext.charCodeAt(input_idx+1);
        chr3 = utftext.charCodeAt(input_idx+2);
        string += String.fromCharCode(((chr1 & 15) << 12) | ((chr2 & 63) << 6) | (chr3 & 63));
        input_idx += 3;
      }
    }

    return string;
  }

};