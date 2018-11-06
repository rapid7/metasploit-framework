#include "ruby.h"
#include "ed25519_ref10.h"

static VALUE mEd25519 = Qnil;
static VALUE mEd25519_Provider = Qnil;
static VALUE mEd25519_Provider_Ref10 = Qnil;

static VALUE mEd25519_Provider_Ref10_create_keypair(VALUE self, VALUE seed);
static VALUE mEd25519_Provider_Ref10_sign(VALUE self, VALUE signing_key, VALUE msg);
static VALUE mEd25519_Provider_Ref10_verify(VALUE self, VALUE verify_key, VALUE signature, VALUE msg);

void Init_ed25519_ref10()
{
    mEd25519 = rb_define_module("Ed25519");
    mEd25519_Provider = rb_define_module_under(mEd25519, "Provider");
    mEd25519_Provider_Ref10 = rb_define_module_under(mEd25519_Provider, "Ref10");

    rb_define_singleton_method(mEd25519_Provider_Ref10, "create_keypair", mEd25519_Provider_Ref10_create_keypair, 1);
    rb_define_singleton_method(mEd25519_Provider_Ref10, "sign", mEd25519_Provider_Ref10_sign, 2);
    rb_define_singleton_method(mEd25519_Provider_Ref10, "verify", mEd25519_Provider_Ref10_verify, 3);
}

static VALUE mEd25519_Provider_Ref10_create_keypair(VALUE self, VALUE seed)
{
    uint8_t verify_key[PUBLICKEYBYTES];
    uint8_t keypair[SECRETKEYBYTES];

    StringValue(seed);

    if(RSTRING_LEN(seed) != SECRETKEYBYTES / 2) {
        rb_raise(rb_eArgError, "seed must be exactly %d bytes", SECRETKEYBYTES / 2);
    }

    crypto_sign_ed25519_ref10_seed_keypair(verify_key, keypair, (uint8_t *)RSTRING_PTR(seed));

    return rb_str_new((const char *)keypair, SECRETKEYBYTES);
}

static VALUE mEd25519_Provider_Ref10_sign(VALUE self, VALUE signing_key, VALUE msg)
{
    uint8_t *sig_and_msg;
    uint64_t sig_and_msg_len;
    VALUE result;

    StringValue(signing_key);
    StringValue(msg);

    if(RSTRING_LEN(signing_key) != SECRETKEYBYTES) {
        rb_raise(rb_eArgError, "private signing keys must be %d bytes", SECRETKEYBYTES);
    }

    sig_and_msg = (uint8_t *)xmalloc(SIGNATUREBYTES + RSTRING_LEN(msg));
    crypto_sign_ed25519_ref10(
        sig_and_msg, &sig_and_msg_len,
        (uint8_t *)RSTRING_PTR(msg), RSTRING_LEN(msg),
        (uint8_t *)RSTRING_PTR(signing_key)
    );

    result = rb_str_new((const char *)sig_and_msg, SIGNATUREBYTES);
    xfree(sig_and_msg);

    return result;
}

static VALUE mEd25519_Provider_Ref10_verify(VALUE self, VALUE verify_key, VALUE signature, VALUE msg)
{
    uint8_t *sig_and_msg, *buffer;
    uint64_t sig_and_msg_len, buffer_len;
    int result;

    StringValue(verify_key);
    StringValue(signature);
    StringValue(msg);

    if(RSTRING_LEN(verify_key) != PUBLICKEYBYTES) {
      rb_raise(rb_eArgError, "public verify keys must be %d bytes", PUBLICKEYBYTES);
    }

    if(RSTRING_LEN(signature) != SIGNATUREBYTES) {
      rb_raise(rb_eArgError, "signatures must be %d bytes", SIGNATUREBYTES);
    }

    sig_and_msg_len = SIGNATUREBYTES + RSTRING_LEN(msg);
    sig_and_msg = (unsigned char *)xmalloc(sig_and_msg_len);
    buffer      = (unsigned char *)xmalloc(sig_and_msg_len);
    memcpy(sig_and_msg, RSTRING_PTR(signature), SIGNATUREBYTES);
    memcpy(sig_and_msg + SIGNATUREBYTES, RSTRING_PTR(msg), RSTRING_LEN(msg));

    result = crypto_sign_open_ed25519_ref10(
        buffer, &buffer_len,
        sig_and_msg, sig_and_msg_len,
        (uint8_t *)RSTRING_PTR(verify_key)
    );

    xfree(sig_and_msg);
    xfree(buffer);

    return result == 0 ? Qtrue : Qfalse;
}
