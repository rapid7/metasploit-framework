#include "includes.h"
#include <ruby.h>

static VALUE mBCryptPbkdf;
static VALUE cBCryptPbkdfEngine;

/* Given a secret and a salt a key and the number of rounds and returns the encrypted secret
*/
static VALUE bc_crypt_pbkdf(VALUE self, VALUE pass, VALUE salt, VALUE keylen, VALUE rounds) {
  size_t okeylen = NUM2ULONG(keylen);
  u_int8_t* okey = xmalloc(keylen);
  VALUE out;

  int ret = bcrypt_pbkdf(
    StringValuePtr(pass), RSTRING_LEN(pass),
    (const u_int8_t*)StringValuePtr(salt), RSTRING_LEN(salt),
    okey, okeylen,
    NUM2ULONG(rounds));
  if (ret < 0)
    return Qnil;
  out = rb_str_new((const char*)okey, okeylen);
  xfree(okey);
  return out;
}

static VALUE bc_crypt_hash(VALUE self, VALUE pass, VALUE salt) {
  u_int8_t hash[BCRYPT_HASHSIZE];
  if (RSTRING_LEN(pass) != 64U)
    return Qnil;
  if (RSTRING_LEN(salt) != 64U)
    return Qnil;
  bcrypt_hash((const u_int8_t*)StringValuePtr(pass), (const u_int8_t*)StringValuePtr(salt), hash);
  return rb_str_new((const char*)hash, sizeof(hash));
}


/* Create the BCryptPbkdf and BCryptPbkdf::Engine modules, and populate them with methods. */
void Init_bcrypt_pbkdf_ext(){
    mBCryptPbkdf = rb_define_module("BCryptPbkdf");
    cBCryptPbkdfEngine = rb_define_class_under(mBCryptPbkdf, "Engine", rb_cObject);

    rb_define_singleton_method(cBCryptPbkdfEngine, "__bc_crypt_pbkdf", bc_crypt_pbkdf, 4);
    rb_define_singleton_method(cBCryptPbkdfEngine, "__bc_crypt_hash", bc_crypt_hash, 2);
}