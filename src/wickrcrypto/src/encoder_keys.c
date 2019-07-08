
#include "encoder_keys.h"
#include "memory.h"

wickr_encoder_keys_t *wickr_encoder_keys_create(wickr_cipher_key_t *payload_key, wickr_ec_key_t *exchange_key)
{
    if (!payload_key || !exchange_key) {
        return NULL;
    }
    
    wickr_encoder_keys_t *encoder_keys = (wickr_encoder_keys_t *)wickr_alloc_zero(sizeof(wickr_encoder_keys_t));
    
    if (!encoder_keys) {
        return NULL;
    }
    
    encoder_keys->exchange_key = exchange_key;
    encoder_keys->payload_key = payload_key;
    
    return encoder_keys;
}

wickr_encoder_keys_t *wickr_encoder_keys_copy(const wickr_encoder_keys_t *encoder_keys)
{
    if (!encoder_keys) {
        return NULL;
    }
    
    wickr_cipher_key_t *payload_key_copy = wickr_cipher_key_copy(encoder_keys->payload_key);
    
    if (!payload_key_copy) {
        return NULL;
    }
    
    wickr_ec_key_t *exchange_key_copy = wickr_ec_key_copy(encoder_keys->exchange_key);
    
    if (!exchange_key_copy) {
        wickr_cipher_key_destroy(&payload_key_copy);
        return NULL;
    }
    
    wickr_encoder_keys_t *copy = wickr_encoder_keys_create(payload_key_copy, exchange_key_copy);
    
    if (!copy) {
        wickr_cipher_key_destroy(&payload_key_copy);
        wickr_ec_key_destroy(&exchange_key_copy);
    }
    
    return copy;
}

void wickr_encoder_keys_destroy(wickr_encoder_keys_t **encoder_keys)
{
    if (!encoder_keys || !*encoder_keys) {
        return;
    }
    
    wickr_cipher_key_destroy(&(*encoder_keys)->payload_key);
    wickr_ec_key_destroy(&(*encoder_keys)->exchange_key);
    wickr_free(*encoder_keys);
    *encoder_keys = NULL;
}

wickr_encoder_keys_t *wickr_encoder_keys_gen_default_random(wickr_crypto_engine_t engine)
{
    wickr_cipher_key_t *payload_key = engine.wickr_crypto_engine_cipher_key_random(engine.default_cipher);
    wickr_ec_key_t *exchange_key = engine.wickr_crypto_engine_ec_rand_key(engine.default_curve);
    
    wickr_encoder_keys_t *encoder_keys = wickr_encoder_keys_create(payload_key, exchange_key);
    
    if (!encoder_keys) {
        wickr_cipher_key_destroy(&payload_key);
        wickr_ec_key_destroy(&exchange_key);
    }
    
    return encoder_keys;
}
