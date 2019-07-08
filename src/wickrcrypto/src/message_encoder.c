
#include "message_encoder.h"
#include "memory.h"
#include "protocol.h"

wickr_message_encoder_t *wickr_message_encoder_create(wickr_crypto_engine_t engine,
                                                      wickr_identity_chain_t *sender_identity,
                                                      wickr_cipher_key_t *header_key,
                                                      uint8_t protocol_version)
{
    if (!header_key) {
        return NULL;
    }
    
    if (protocol_version < OLDEST_PACKET_VERSION || protocol_version > CURRENT_PACKET_VERSION) {
        return NULL;
    }
    
    wickr_message_encoder_t *encoder = wickr_alloc_zero(sizeof(wickr_message_encoder_t));
    
    if (!encoder) {
        return NULL;
    }
    
    encoder->crypto_engine = engine;
    encoder->header_key = header_key;
    encoder->protocol_version = protocol_version;
    
    return encoder;
}

wickr_message_encoder_t *wickr_message_encoder_copy(const wickr_message_encoder_t *encoder)
{
    if (!encoder) {
        return NULL;
    }
    
    wickr_identity_chain_t *sender_identity_copy = wickr_identity_chain_copy(encoder->sender_identity);
    
    if (!sender_identity_copy) {
        return NULL;
    }
    
    wickr_cipher_key_t *header_key_copy = wickr_cipher_key_copy(encoder->header_key);
    
    if (!header_key_copy) {
        wickr_identity_chain_destroy(&sender_identity_copy);
        return NULL;
    }
    
    wickr_message_encoder_t *copy = wickr_message_encoder_create(encoder->crypto_engine,
                                                                 sender_identity_copy,
                                                                 header_key_copy,
                                                                 encoder->protocol_version);
    
    if (!copy) {
        wickr_identity_chain_destroy(&sender_identity_copy);
        wickr_cipher_key_destroy(&header_key_copy);
    }
    
    return copy;
    
}

void wickr_message_encoder_destroy(wickr_message_encoder_t **encoder)
{
    if (!encoder || !*encoder) {
        return;
    }
    
    wickr_identity_chain_destroy(&(*encoder)->sender_identity);
    wickr_cipher_key_destroy(&(*encoder)->header_key);
    
    wickr_free(*encoder);
    *encoder = NULL;
}

wickr_encoder_result_t *wickr_message_encoder_encode(const wickr_message_encoder_t *encoder,
                                                     const wickr_payload_t *payload,
                                                     const wickr_node_array_t *nodes)
{    
    return wickr_message_encoder_encode_custom(encoder, payload, nodes, wickr_encoder_keys_gen_default_random);
}

wickr_encoder_result_t *wickr_message_encoder_encode_custom(const wickr_message_encoder_t *encoder,
                                                            const wickr_payload_t *payload,
                                                            const wickr_node_array_t *nodes,
                                                            wickr_encoder_key_generation_func keygen_func)
{
    if (!encoder || !payload || !nodes) {
        return NULL;
    }
    
    wickr_encoder_keys_t *encoder_keys = keygen_func(encoder->crypto_engine);
    
    wickr_packet_t *generated_packet = wickr_packet_create_from_components(&encoder->crypto_engine,
                                                                           encoder->header_key,
                                                                           encoder_keys->payload_key,
                                                                           encoder_keys->exchange_key,
                                                                           payload,
                                                                           nodes,
                                                                           encoder->sender_identity,
                                                                           encoder->protocol_version);
    
    wickr_encoder_result_t *result = wickr_encoder_result_create(wickr_cipher_key_copy(encoder_keys->payload_key),
                                                                 generated_packet);
    
    wickr_encoder_keys_destroy(&encoder_keys);
    
    if (!result) {
        wickr_packet_destroy(&generated_packet);
    }
    
    return result;
}
