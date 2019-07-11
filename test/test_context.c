#include "cspec.h"
#include "test_buffer.h"
#include "externs.h"
#include "crypto_engine.h"
#include "wickr_ctx.h"
#include "encoder_result.h"

#include <string.h>

/*
 * Test the different functions that create the wickr_ctx_gen_result_t, including the following:
 *   - wickr_ctx_gen_new
 *   - wickr_ctx_gen_with_passphrase
 *   - wickr_ctx_gen_with_recovery
 *   - wickr_ctx_gen_with_root_keys
 */
DESCRIBE(wickr_ctx_generate, "wickr_ctx: test generation")
{
    init_test();

    wickr_ctx_gen_result_t *result;
    
    char *system_name = "SYSTEM_NAME_FOR_CONTEXT_TEST";
    wickr_buffer_t *dev_buf = wickr_buffer_create((uint8_t *)system_name, strlen(system_name));
    wickr_dev_info_t *dev_info = create_dev_info(dev_buf);
    
    wickr_buffer_t *rand_id = engine.wickr_crypto_engine_crypto_random(IDENTIFIER_LEN);
    
    IT("can be generated with dev_info and an id")
    {
        SHOULD_NOT_BE_NULL(result = wickr_ctx_gen_new(engine, dev_info, rand_id))
    }
    END_IT

    IT("should be able to make a copy of itself")
    {
        wickr_ctx_gen_result_t *copy_result;
        
        SHOULD_NOT_BE_NULL(copy_result = wickr_ctx_gen_result_copy(result))
        if (copy_result != NULL) {
            wickr_ctx_gen_result_destroy(&copy_result);
            SHOULD_BE_NULL(copy_result)
        }
    }
    END_IT
    
    IT("can be generated with dev_info and specified root keys")
    {
        wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
        wickr_root_keys_t *keys = wickr_root_keys_generate(&engine);
        
        SHOULD_NOT_BE_NULL(keys);
        
        wickr_ctx_gen_result_t *root_key_result = wickr_ctx_gen_with_root_keys(engine, dev_info, keys, rand_id);
        
        SHOULD_NOT_BE_NULL(root_key_result);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(root_key_result->root_keys->node_storage_root->key_data, keys->node_storage_root->key_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(root_key_result->root_keys->remote_storage_root->key_data, keys->remote_storage_root->key_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(root_key_result->root_keys->node_signature_root->pri_data, keys->node_signature_root->pri_data, NULL));

        wickr_ctx_gen_result_destroy(&root_key_result);
        wickr_root_keys_destroy(&keys);
        
        SHOULD_BE_NULL(root_key_result);
    }
    END_IT
    
    IT("can be generated with a specified signing key")
    {
        wickr_ec_key_t *sig_key = engine.wickr_crypto_engine_ec_rand_key(engine.default_curve);
        SHOULD_NOT_BE_NULL(sig_key);
        
        wickr_ctx_gen_result_t *sig_key_result = wickr_ctx_gen_new_with_sig_key(engine, dev_info, sig_key, rand_id);
        
        SHOULD_NOT_BE_NULL(sig_key_result);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(sig_key_result->root_keys->node_signature_root->pri_data, sig_key->pri_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(sig_key_result->root_keys->node_signature_root->pub_data, sig_key->pub_data, NULL));

        wickr_ctx_gen_result_destroy(&sig_key_result);
        wickr_ec_key_destroy(&sig_key);
    }
    END_IT
    
    char *passphrase = "password";
    wickr_buffer_t *passphrase_bfr = wickr_buffer_create((uint8_t*)passphrase, strlen(passphrase));
    wickr_buffer_t *recovery = NULL;
    
    
    IT("can export an recovery for you")
    {
        recovery = wickr_ctx_gen_result_make_recovery(result);
        SHOULD_NOT_BE_NULL(recovery);
    }
    END_IT
    
    IT("it can be generated with an recovery + recovery key")
    {
        wickr_ctx_gen_result_t *with_recovery_result = NULL;
        
        SHOULD_NOT_BE_NULL(with_recovery_result = wickr_ctx_gen_with_recovery(engine, dev_info, recovery, result->recovery_key, rand_id))
        
        /* Verify that the new context has all the same values as the old one */
        SHOULD_BE_TRUE(wickr_buffer_is_equal(with_recovery_result->root_keys->node_storage_root->key_data,
                                             result->root_keys->node_storage_root->key_data,
                                             NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(with_recovery_result->root_keys->remote_storage_root->key_data,
                                             result->root_keys->remote_storage_root->key_data,
                                             NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(with_recovery_result->root_keys->node_signature_root->pri_data,
                                             result->root_keys->node_signature_root->pri_data,
                                             NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(with_recovery_result->recovery_key->key_data,
                                             result->recovery_key->key_data, NULL));
        
        if (result != NULL) {
            wickr_ctx_gen_result_t *copyResult;
            
            SHOULD_NOT_BE_NULL(copyResult = wickr_ctx_gen_result_copy(result))
            if (copyResult != NULL) {
                wickr_ctx_gen_result_destroy(&copyResult);
                SHOULD_BE_NULL(copyResult)
            }
        }
        
        if (result != NULL) {
            wickr_ctx_gen_result_t *copy_result;
            
            SHOULD_NOT_BE_NULL(copy_result = wickr_ctx_gen_result_copy(result))
            
            if (copy_result != NULL) {
                wickr_ctx_gen_result_destroy(&copy_result);
                SHOULD_BE_NULL(copy_result)
            }
            wickr_ctx_gen_result_destroy(&with_recovery_result);
            SHOULD_BE_NULL(with_recovery_result)
        }
    }
    END_IT
    
    wickr_buffer_t *exported_escrow_key = NULL;
    
    IT("can export your recovery key")
    {
        exported_escrow_key = wickr_ctx_gen_export_recovery_key_passphrase(result, passphrase_bfr);
        SHOULD_NOT_BE_NULL(exported_escrow_key);
        
        wickr_cipher_key_t *imported = wickr_ctx_gen_import_recovery_key_passphrase(result->ctx->engine, exported_escrow_key, passphrase_bfr);
        
        SHOULD_NOT_BE_NULL(imported);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(imported->key_data, result->recovery_key->key_data, NULL));
        wickr_cipher_key_destroy(&imported);
    }
    END_IT
    
    IT("can be generated with a passphrase, recovery")
    {
        
        wickr_ctx_gen_result_t *with_passphrase_result = NULL;
        
        SHOULD_NOT_BE_NULL(with_passphrase_result = wickr_ctx_gen_with_passphrase(engine, dev_info, exported_escrow_key, passphrase_bfr, recovery, rand_id))
        
        /* Verify that the new context has all the same values as the old one */
        SHOULD_BE_TRUE(wickr_buffer_is_equal(with_passphrase_result->root_keys->node_storage_root->key_data,
                                             result->root_keys->node_storage_root->key_data,
                                             NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(with_passphrase_result->root_keys->remote_storage_root->key_data,
                                             result->root_keys->remote_storage_root->key_data,
                                             NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(with_passphrase_result->root_keys->node_signature_root->pri_data,
                                             result->root_keys->node_signature_root->pri_data,
                                             NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(with_passphrase_result->recovery_key->key_data,
                                             result->recovery_key->key_data, NULL));
        
        if (result != NULL) {
            wickr_ctx_gen_result_t *copyResult;
            
            SHOULD_NOT_BE_NULL(copyResult = wickr_ctx_gen_result_copy(result))
            if (copyResult != NULL) {
                wickr_ctx_gen_result_destroy(&copyResult);
                SHOULD_BE_NULL(copyResult)
            }
            
            wickr_ctx_gen_result_destroy(&with_passphrase_result);
            SHOULD_BE_NULL(with_passphrase_result)
        }
    }
    END_IT
    
    wickr_buffer_destroy(&exported_escrow_key);
    wickr_buffer_destroy(&passphrase_bfr);
    wickr_buffer_destroy(&rand_id);
    wickr_dev_info_destroy(&dev_info);
    wickr_buffer_destroy(&dev_buf);
    wickr_buffer_destroy(&recovery);
    wickr_ctx_gen_result_destroy(&result);

}
END_DESCRIBE

static void __test_cipher_method(wickr_ctx_t *ctx, int size, int iterations, wickr_cipher_result_t *(*enc_op)(const wickr_ctx_t *ctx, const wickr_buffer_t *buffer), wickr_buffer_t *(*dec_op)(const wickr_ctx_t *ctx, const wickr_cipher_result_t *result))
{
    wickr_buffer_t *rand_data = engine.wickr_crypto_engine_crypto_random(size);
    
    wickr_cipher_result_t *enc_data = enc_op(ctx, rand_data);
    
    SHOULD_NOT_BE_NULL(enc_data);
    SHOULD_BE_FALSE(wickr_buffer_is_equal(enc_data->cipher_text, rand_data, NULL));
    
    for (int i = 0; i < 1000; i++) {
        wickr_cipher_result_t *one_encrypt = enc_op(ctx, rand_data);
        SHOULD_BE_FALSE(wickr_buffer_is_equal(one_encrypt->cipher_text, enc_data->cipher_text, NULL));
        wickr_cipher_result_destroy(&one_encrypt);
    }
    
    wickr_buffer_t *dec_data = dec_op(ctx, enc_data);
    
    SHOULD_NOT_BE_NULL(dec_data);
    SHOULD_BE_TRUE(wickr_buffer_is_equal(dec_data, rand_data, NULL));
    
    wickr_cipher_result_destroy(&enc_data);
    wickr_buffer_destroy(&dec_data);
    wickr_buffer_destroy(&rand_data);

}

void wickr_ctx_verify_equal(wickr_ctx_t *ctx, wickr_ctx_t *deserialized)
{
    SHOULD_NOT_BE_NULL(deserialized);
    
    SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized->id_chain->node->identifier,
                                         ctx->id_chain->node->identifier, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized->id_chain->root->sig_key->pri_data,
                                         ctx->id_chain->root->sig_key->pri_data, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized->id_chain->root->identifier,
                                         ctx->id_chain->root->identifier, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized->msg_encoder->header_key->key_data,
                                         ctx->msg_encoder->header_key->key_data, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized->msg_encoder->sender_identity->root->identifier, ctx->msg_encoder->sender_identity->root->identifier, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized->msg_encoder->sender_identity->root->sig_key->pri_data, ctx->msg_encoder->sender_identity->root->sig_key->pri_data, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized->msg_encoder->sender_identity->node->identifier, ctx->msg_encoder->sender_identity->node->identifier, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized->msg_encoder->sender_identity->node->sig_key->pri_data, ctx->msg_encoder->sender_identity->node->sig_key->pri_data, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized->storage_keys->local->key_data,
                                         ctx->storage_keys->local->key_data, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized->storage_keys->remote->key_data,
                                         ctx->storage_keys->remote->key_data, NULL));
    SHOULD_EQUAL(deserialized->msg_encoder->protocol_version, ctx->msg_encoder->protocol_version);
}

DESCRIBE(wickr_ctx_functions, "wickr_ctx: general functions")
{
    init_test();
    
    char *system_name = "SYSTEM_NAME_FOR_CONTEXT_TEST";
    wickr_buffer_t *dev_buf = wickr_buffer_create((uint8_t *)system_name, strlen(system_name));
    wickr_dev_info_t *dev_info = create_dev_info(dev_buf);
    
    wickr_buffer_t *rand_id = engine.wickr_crypto_engine_crypto_random(IDENTIFIER_LEN);
    
    wickr_ctx_gen_result_t *ctx_res = NULL;
    SHOULD_NOT_BE_NULL(ctx_res = wickr_ctx_gen_new(engine, dev_info, rand_id))

    wickr_ctx_t *ctx = ctx_res->ctx;
    
    IT("can be serialized and deserialized")
    {
        wickr_buffer_t *serialized = wickr_ctx_serialize(ctx);
        SHOULD_NOT_BE_NULL(serialized);
        
        wickr_ctx_t *deserialized = wickr_ctx_create_from_buffer(engine,
                                                                 wickr_dev_info_copy(dev_info),
                                                                 serialized);
        wickr_ctx_verify_equal(ctx, deserialized);
        
        wickr_buffer_destroy(&serialized);
        wickr_ctx_destroy(&deserialized);
    }
    END_IT
    
    IT("can be exported and imported")
    {
        wickr_buffer_t *test_passphrase = engine.wickr_crypto_engine_crypto_random(32);
        wickr_buffer_t *serialized = wickr_ctx_export(ctx, test_passphrase);
        SHOULD_NOT_BE_NULL(serialized);
        
        wickr_ctx_t *deserialized = wickr_ctx_import(engine,
                                                     wickr_dev_info_copy(dev_info),
                                                     serialized,
                                                     test_passphrase);
        
        wickr_ctx_verify_equal(ctx, deserialized);
        
        wickr_buffer_destroy(&serialized);
        wickr_ctx_destroy(&deserialized);
        wickr_buffer_destroy(&test_passphrase);
    }
    END_IT
    
    IT("should be able to export storage keys with a passphrase")
    {
        wickr_buffer_t *rand_pass = engine.wickr_crypto_engine_crypto_random(IDENTIFIER_LEN);
        
        wickr_buffer_t *exported = wickr_ctx_export_storage_keys(ctx, rand_pass);
        
        SHOULD_NOT_BE_NULL(exported);
        
        wickr_storage_keys_t *imported =  wickr_ctx_import_storage_keys(engine, exported, rand_pass);
        
        SHOULD_NOT_BE_NULL(imported);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(imported->local->key_data, ctx->storage_keys->local->key_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(imported->remote->key_data, ctx->storage_keys->remote->key_data, NULL));
        
        
        wickr_buffer_destroy(&rand_pass);
        wickr_buffer_destroy(&exported);
        wickr_storage_keys_destroy(&imported);
    }
    END_IT
    
    IT("should be able to encrypt local data with random IVs")
    {
        __test_cipher_method(ctx, 10000, 1000, wickr_ctx_cipher_local, wickr_ctx_decipher_local);
    }
    END_IT
    
    IT("should be able to encrypt remote data with random IVs")
    {
        __test_cipher_method(ctx, 10000, 1000, wickr_ctx_cipher_remote, wickr_ctx_decipher_remote);
    }
    END_IT
    
    IT("should encrypt remote data differently than local data")
    {
        wickr_buffer_t *rand_data = engine.wickr_crypto_engine_crypto_random(10000);
        
        wickr_cipher_result_t *cipher_result = wickr_ctx_cipher_local(ctx, rand_data);
        SHOULD_NOT_BE_NULL(cipher_result);
        SHOULD_BE_NULL(wickr_ctx_decipher_remote(ctx, cipher_result));
        
        wickr_cipher_result_destroy(&cipher_result);
        
        cipher_result = wickr_ctx_cipher_remote(ctx, rand_data);
        
        SHOULD_NOT_BE_NULL(cipher_result);
        SHOULD_BE_NULL(wickr_ctx_decipher_local(ctx, cipher_result));
        
        wickr_cipher_result_destroy(&cipher_result);
        wickr_buffer_destroy(&rand_data);
    }
    END_IT
    
    IT("should be able to generate ephemeral keypairs")
    {
        wickr_ephemeral_keypair_t *keypair = wickr_ctx_ephemeral_keypair_gen(ctx, 100);
        SHOULD_NOT_BE_NULL(keypair);
        SHOULD_EQUAL(100, keypair->identifier);
        
        SHOULD_BE_TRUE(engine.wickr_crypto_engine_ec_verify(keypair->signature, ctx->id_chain->node->sig_key, keypair->ec_key->pub_data));
        
        SHOULD_BE_TRUE(wickr_ephemeral_keypair_verify_owner(keypair, &engine, ctx->id_chain->node));
        SHOULD_BE_FALSE(wickr_ephemeral_keypair_verify_owner(keypair, &engine, ctx->id_chain->root));
        
        wickr_ephemeral_keypair_destroy(&keypair);
    }
    END_IT
    
    wickr_buffer_destroy(&rand_id);
    wickr_dev_info_destroy(&dev_info);
    wickr_buffer_destroy(&dev_buf);
    
    wickr_ctx_gen_result_destroy(&ctx_res);
}
END_DESCRIBE

void __test_packet_decode(wickr_ctx_t *ctx_user1,
                          wickr_ctx_t *ctx_user2,
                          wickr_node_t *node_user2,
                          wickr_encoder_result_t *encode_pkt,
                          wickr_buffer_t *body_data,
                          wickr_buffer_t *channel_tag,
                          uint64_t content_type,
                          wickr_ephemeral_info_t ephemeral_data)
{
    wickr_ctx_packet_t *in_packet = NULL;
    
    wickr_buffer_t *packet_buffer = wickr_packet_serialize(encode_pkt->packet);
    
    SHOULD_NOT_BE_NULL(in_packet = wickr_ctx_parse_packet(ctx_user2, packet_buffer, ctx_user1->id_chain))
    
    if (in_packet != NULL) {
        
        SHOULD_NOT_BE_NULL(in_packet->parse_result->key_exchange);
        SHOULD_EQUAL(in_packet->parse_result->err, E_SUCCESS);
        SHOULD_NOT_BE_NULL(in_packet->packet);
        SHOULD_NOT_BE_NULL(in_packet->packet->content);
        SHOULD_NOT_BE_NULL(in_packet->packet->signature);
        SHOULD_EQUAL(in_packet->packet->version, ctx_user1->msg_encoder->protocol_version);
        SHOULD_NOT_BE_NULL(in_packet->parse_result->enc_payload);
        SHOULD_NOT_BE_NULL(in_packet->parse_result->key_exchange_set);
        SHOULD_EQUAL(in_packet->parse_result->signature_status, PACKET_SIGNATURE_VALID);
        
        wickr_decode_result_t *decode_result;
        SHOULD_NOT_BE_NULL(decode_result = wickr_ctx_decode_packet(ctx_user2, in_packet, node_user2->ephemeral_keypair->ec_key))
        
        SHOULD_BE_FALSE(wickr_buffer_is_equal(decode_result->decrypted_payload->body, in_packet->packet->content, NULL))
        SHOULD_BE_FALSE(wickr_buffer_is_equal(body_data, in_packet->packet->content, NULL));
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(body_data, decode_result->decrypted_payload->body, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(channel_tag, decode_result->decrypted_payload->meta->channel_tag, NULL));
        SHOULD_EQUAL(ephemeral_data.bor, decode_result->decrypted_payload->meta->ephemerality_settings.bor);
        SHOULD_EQUAL(ephemeral_data.ttl, decode_result->decrypted_payload->meta->ephemerality_settings.ttl);
        SHOULD_EQUAL(content_type, decode_result->decrypted_payload->meta->content_type);
        
        wickr_decode_result_destroy(&decode_result);
        wickr_ctx_packet_destroy(&in_packet);
    }
    
     wickr_buffer_destroy(&packet_buffer);
}

DESCRIBE(wickr_ctx_send_pkt, "wickr_ctx: test sending packet")
{
    init_test();
    
    // Create user 1
    char *name_user1 = "alice@wickr.com";
    char *name_dev1_user1 = "alice:DEVICE1";
    wickr_buffer_t *dev_buf_user1 = wickr_buffer_create((uint8_t *)name_dev1_user1, strlen(name_dev1_user1));

    wickr_node_t *node_user1 = create_user_node(name_user1, dev_buf_user1);
    wickr_ctx_t *ctx_user1 = create_context(node_user1);
    
    node_user1->dev_id = wickr_buffer_copy(ctx_user1->dev_info->msg_proto_id);
    wickr_buffer_destroy(&dev_buf_user1);
    
    // Create user 2
    char *name_user2 = "bob@wickr.com";
    char *name_dev1_user2 = "bpb:DEVICE1";
    wickr_buffer_t *dev_buf_user2 = wickr_buffer_create((uint8_t *)name_dev1_user2, strlen(name_dev1_user2));
    
    wickr_node_t *node_user2 = create_user_node(name_user2, dev_buf_user2);
    wickr_ctx_t *ctx_user2 = create_context(node_user2);
    node_user2->dev_id = wickr_buffer_copy(ctx_user2->dev_info->msg_proto_id);
    wickr_buffer_destroy(&dev_buf_user2);
    
    wickr_node_array_t *recipients = wickr_node_array_new(2);
    
    wickr_node_array_set_item(recipients, 0, node_user2);
    wickr_node_array_set_item(recipients, 1, node_user1);
        
    wickr_ephemeral_info_t ephemeral_data = { 64000, 3600 };
    wickr_buffer_t *channel_tag = engine.wickr_crypto_engine_crypto_random(64);
    uint16_t content_type = 3000;
    wickr_packet_meta_t *metadata = wickr_packet_meta_create(ephemeral_data, channel_tag, content_type);
    
    char *body = "Hello World!";
    wickr_buffer_t *body_data = wickr_buffer_create((uint8_t*)body, strlen(body));
    wickr_payload_t *payload = wickr_payload_create(metadata, body_data);

    wickr_encoder_result_t *encode_pkt = NULL;
    
    IT("should encode packets")
    {
        SHOULD_NOT_BE_NULL(encode_pkt = wickr_ctx_encode_packet(ctx_user1, payload, recipients))
        
    }
    END_IT
    
    IT ("should fail to create a packet using a failed identity status")
    {
        wickr_node_t *first_recipient = wickr_node_array_fetch_item(recipients, 0);
        first_recipient->id_chain->status = IDENTITY_CHAIN_STATUS_INVALID;
        
        wickr_encoder_result_t *bad_packet = wickr_ctx_encode_packet(ctx_user1, payload, recipients);
        SHOULD_BE_NULL(bad_packet);
        first_recipient->id_chain->status = IDENTITY_CHAIN_STATUS_UNKNOWN;
    }
    END_IT
    
    IT("should fail to create a packet using an invalid recipient ephemeral keypair")
    {
        wickr_node_array_t *recipients_copy = wickr_node_array_copy(recipients);
        wickr_node_t *first_recipient = wickr_node_array_fetch_item(recipients_copy, 0);
        
        wickr_buffer_t *random_data = engine.wickr_crypto_engine_crypto_random(64);
        
        wickr_ecdsa_result_destroy(&first_recipient->ephemeral_keypair->signature);
        
        first_recipient->ephemeral_keypair->signature = wickr_identity_sign(first_recipient->id_chain->node, &engine, random_data);
        wickr_buffer_destroy(&random_data);
        
        wickr_encoder_result_t *bad_packet = wickr_ctx_encode_packet(ctx_user1, payload, recipients_copy);
        SHOULD_BE_NULL(bad_packet);
        
        /* Force a valid identity chain state, make sure it still fails */
        first_recipient->id_chain->status = IDENTITY_CHAIN_STATUS_VALID;
        
        bad_packet = wickr_ctx_encode_packet(ctx_user1, payload, recipients_copy);
        SHOULD_BE_NULL(bad_packet);
        
        wickr_array_destroy(&recipients_copy, true);
    }
    END_IT
    
    IT("should fail to create a packet using an invalid recipient signature")
    {
        wickr_node_array_t *recipients_copy = wickr_node_array_copy(recipients);
        wickr_node_t *first_recipient = wickr_node_array_fetch_item(recipients_copy, 0);
        
        wickr_buffer_t *random_data = engine.wickr_crypto_engine_crypto_random(64);
        
        wickr_ecdsa_result_destroy(&first_recipient->id_chain->node->signature);
        
        first_recipient->id_chain->node->signature = wickr_identity_sign(first_recipient->id_chain->node, &engine, random_data);
        wickr_buffer_destroy(&random_data);
        
        wickr_encoder_result_t *bad_packet = wickr_ctx_encode_packet(ctx_user1, payload, recipients_copy);
        SHOULD_BE_NULL(bad_packet);
        
        wickr_array_destroy(&recipients_copy, true);
    }
    END_IT
    
    IT("should parse packets for non decoding purposes")
    {
        wickr_ctx_packet_t *in_packet = NULL;
        
        wickr_buffer_t *packet_buffer = wickr_packet_serialize(encode_pkt->packet);
        
        if (encode_pkt != NULL) {
            
            SHOULD_NOT_BE_NULL(in_packet = wickr_ctx_parse_packet_no_decode(ctx_user2, packet_buffer, ctx_user1->id_chain));
            SHOULD_BE_NULL(in_packet->parse_result->key_exchange);
            SHOULD_EQUAL(in_packet->parse_result->err, E_SUCCESS);
            SHOULD_NOT_BE_NULL(in_packet->packet);
            SHOULD_NOT_BE_NULL(in_packet->packet->content);
            SHOULD_NOT_BE_NULL(in_packet->packet->signature);
            SHOULD_EQUAL(in_packet->packet->version, DEFAULT_PKT_ENC_VERSION);
            SHOULD_NOT_BE_NULL(in_packet->parse_result->enc_payload);
            SHOULD_NOT_BE_NULL(in_packet->parse_result->key_exchange_set);
            SHOULD_EQUAL(in_packet->parse_result->signature_status, PACKET_SIGNATURE_VALID);
            
            wickr_decode_result_t *decode_result = wickr_ctx_decode_packet(ctx_user2, in_packet, node_user2->ephemeral_keypair->ec_key);
            SHOULD_NOT_BE_NULL(decode_result);
            SHOULD_BE_NULL(decode_result->decrypted_payload);
            SHOULD_BE_NULL(decode_result->payload_key);
            SHOULD_EQUAL(decode_result->err, ERROR_KEY_EXCHANGE_FAILED);
            wickr_decode_result_destroy(&decode_result);
        }
        
        wickr_ctx_packet_destroy(&in_packet);
        wickr_buffer_destroy(&packet_buffer);
    }
    END_IT

    IT("should parse packets for decoding")
    {
        __test_packet_decode(ctx_user1, ctx_user2, node_user2, encode_pkt, body_data, channel_tag, content_type, ephemeral_data);
        wickr_encoder_result_destroy(&encode_pkt);
    }
    END_IT
    
    IT("should support encoding and decoding older verisons of packets for stagged rollout scenarios")
    {
        for (uint8_t i = OLDEST_PACKET_VERSION; i <= CURRENT_PACKET_VERSION; i++) {
            ctx_user1->msg_encoder->protocol_version = i;
            SHOULD_NOT_BE_NULL(encode_pkt = wickr_ctx_encode_packet(ctx_user1, payload, recipients))
            __test_packet_decode(ctx_user1, ctx_user2, node_user2, encode_pkt, body_data, channel_tag, content_type, ephemeral_data);
            wickr_encoder_result_destroy(&encode_pkt);
        }
    }
    END_IT
    
    wickr_node_array_destroy(&recipients);
    wickr_node_destroy(&node_user1);
    wickr_node_destroy(&node_user2);
    wickr_payload_destroy(&payload);
    wickr_ctx_destroy(&ctx_user1);
    wickr_ctx_destroy(&ctx_user2);

}
END_DESCRIBE
