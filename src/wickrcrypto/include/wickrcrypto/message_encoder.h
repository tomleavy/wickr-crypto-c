/*
 * Copyright © 2012-2018 Wickr Inc.  All rights reserved.
 *
 * This code is being released for EDUCATIONAL, ACADEMIC, AND CODE REVIEW PURPOSES
 * ONLY.  COMMERCIAL USE OF THE CODE IS EXPRESSLY PROHIBITED.  For additional details,
 * please see LICENSE
 *
 * THE CODE IS MADE AVAILABLE "AS-IS" AND WITHOUT ANY EXPRESS OR
 * IMPLIED GUARANTEES AS TO FITNESS, MERCHANTABILITY, NON-
 * INFRINGEMENT OR OTHERWISE. IT IS NOT BEING PROVIDED IN TRADE BUT ON
 * A VOLUNTARY BASIS ON BEHALF OF THE AUTHOR’S PART FOR THE BENEFIT
 * OF THE LICENSEE AND IS NOT MADE AVAILABLE FOR CONSUMER USE OR ANY
 * OTHER USE OUTSIDE THE TERMS OF THIS LICENSE. ANYONE ACCESSING THE
 * CODE SHOULD HAVE THE REQUISITE EXPERTISE TO SECURE THEIR SYSTEM
 * AND DEVICES AND TO ACCESS AND USE THE CODE FOR REVIEW PURPOSES
 * ONLY. LICENSEE BEARS THE RISK OF ACCESSING AND USING THE CODE. IN
 * PARTICULAR, AUTHOR BEARS NO LIABILITY FOR ANY INTERFERENCE WITH OR
 * ADVERSE EFFECT THAT MAY OCCUR AS A RESULT OF THE LICENSEE
 * ACCESSING AND/OR USING THE CODE ON LICENSEE’S SYSTEM.
 */

#ifndef message_encoder_h
#define message_encoder_h

#include "crypto_engine.h"
#include "encoder_result.h"
#include "encoder_keys.h"

#ifdef __cplusplus
extern "C" {
#endif
    
typedef wickr_encoder_keys_t *(*wickr_encoder_key_generation_func)(wickr_crypto_engine_t);

struct wickr_message_encoder {
    wickr_crypto_engine_t crypto_engine;
    wickr_identity_chain_t *sender_identity;
    wickr_cipher_key_t *header_key;
    uint8_t protocol_version;
};

typedef struct wickr_message_encoder wickr_message_encoder_t;

wickr_message_encoder_t *wickr_message_encoder_create(wickr_crypto_engine_t engine,
                                                      wickr_identity_chain_t *sender_identity,
                                                      wickr_cipher_key_t *header_key,
                                                      uint8_t protocol_version);

wickr_message_encoder_t *wickr_message_encoder_copy(const wickr_message_encoder_t *encoder);

void wickr_message_encoder_destroy(wickr_message_encoder_t **encoder);

wickr_encoder_result_t *wickr_message_encoder_encode(const wickr_message_encoder_t *encoder,
                                                     const wickr_payload_t *payload,
                                                     const wickr_node_array_t *nodes);

wickr_encoder_result_t *wickr_message_encoder_encode_custom(const wickr_message_encoder_t *encoder,
                                                            const wickr_payload_t *payload,
                                                            const wickr_node_array_t *nodes,
                                                            wickr_encoder_key_generation_func keygen_func);
    
#ifdef __cplusplus
}
#endif

#endif /* message_encoder_h */
