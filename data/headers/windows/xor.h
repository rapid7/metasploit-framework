//
// License:
// https://github.com/rapid7/metasploit-framework/blob/master/LICENSE
//

void xor(char* dest, char* src, char key, int len) {
  for (int i = 0; i < len; i++) {
    char c = src[i] ^ key;
    dest[i] = c;
  }
}