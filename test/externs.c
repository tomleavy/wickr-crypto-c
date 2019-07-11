#include "cspec.h"
#include "externs.h"
#include "test_buffer.h"
#include "crypto_engine.h"
#include "wickr_ctx.h"
#include "ephemeral_keypair.h"
#include "util.h"

#include <string.h>

wickr_crypto_engine_t engine;
wickr_buffer_t *dev_salt = NULL;

static uint64_t cur_identifier = 1;


void init_test()
{
    engine = wickr_crypto_engine_get_default();
    
    // Setup SALT for user names
    if (dev_salt == NULL) {
        dev_salt = engine.wickr_crypto_engine_crypto_random(SCRYPT_SALT_SIZE);
    }
}

wickr_buffer_t *hex_char_to_buffer(const char *hex)
{
    wickr_buffer_t hex_buf = { strlen(hex), (uint8_t *)hex };
    return getDataFromHexString(&hex_buf);
}

wickr_dev_info_t *create_dev_info(wickr_buffer_t *system_id)
{
    wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    wickr_dev_info_t *dev_info = wickr_dev_info_create_new(&engine, system_id);
    
    return dev_info;
}

wickr_ctx_t *create_context(wickr_node_t *user_node)
{
    wickr_dev_info_t *dev_info = create_dev_info(user_node->dev_id);
    
    wickr_cipher_key_t *local_key = engine.wickr_crypto_engine_cipher_key_random(engine.default_cipher);
    wickr_cipher_key_t *remote_key = engine.wickr_crypto_engine_cipher_key_random(engine.default_cipher);
    wickr_storage_keys_t *storage_keys = wickr_storage_keys_create(local_key, remote_key);
    
    wickr_ctx_t *ctx;
    SHOULD_NOT_BE_NULL(ctx = wickr_ctx_create(engine, dev_info, wickr_identity_chain_copy(user_node->id_chain), storage_keys))
    
    return ctx;
}


wickr_buffer_t *create_device_identity(uint8_t *dev_str, size_t dev_len)
{
    wickr_buffer_t *dev_id_buffer = wickr_buffer_create(dev_str, dev_len);
    return dev_id_buffer;
}

wickr_ephemeral_keypair_t *generate_keypair(wickr_identity_t *identity)
{
    engine = wickr_crypto_engine_get_default();
    
    wickr_ec_key_t *key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
    wickr_ecdsa_result_t *signature = wickr_identity_sign(identity, &engine, key->pub_data);
    wickr_ephemeral_keypair_t *keypair = wickr_ephemeral_keypair_create(cur_identifier++, key, signature);
    
    return keypair;
}

wickr_identity_chain_t *create_identity_chain(char *user_name)
{
    wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    
    wickr_buffer_t *user_name_buffer = wickr_buffer_create((uint8_t*)user_name, strlen(user_name));
    
    // Generate Hash of the user name
    wickr_buffer_t *user_digest = engine.wickr_crypto_engine_digest(user_name_buffer, dev_salt, DIGEST_SHA_256);
    wickr_buffer_destroy(&user_name_buffer);
    
    wickr_ec_key_t *key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
    
    wickr_identity_t *root_identity = wickr_identity_create(IDENTITY_TYPE_ROOT, user_digest, key, NULL);
    
    wickr_identity_t *node_identity = wickr_node_identity_gen(&engine, root_identity);
    
    return wickr_identity_chain_create(root_identity, node_identity);
}

wickr_node_t *create_user_node(char *user_name, wickr_buffer_t *dev_id)
{
    wickr_identity_chain_t *id_chain = create_identity_chain(user_name);
    wickr_ephemeral_keypair_t *keypair = generate_keypair(id_chain->node);
    wickr_node_t *user_node = wickr_node_create(dev_id, id_chain, keypair);
    
    return user_node;
}

