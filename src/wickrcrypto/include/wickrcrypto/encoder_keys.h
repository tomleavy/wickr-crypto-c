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

#ifndef encoder_keys_h
#define encoder_keys_h

#include "crypto_engine.h"

#ifdef __cplusplus
extern "C" {
#endif
    
struct wickr_encoder_keys {
    wickr_cipher_key_t *payload_key;
    wickr_ec_key_t *exchange_key;
};

typedef struct wickr_encoder_keys wickr_encoder_keys_t;

wickr_encoder_keys_t *wickr_encoder_keys_create(wickr_cipher_key_t *payload_key, wickr_ec_key_t *exchange_key);

wickr_encoder_keys_t *wickr_encoder_keys_copy(const wickr_encoder_keys_t *encoder_keys);

void wickr_encoder_keys_destroy(wickr_encoder_keys_t **encoder_keys);

wickr_encoder_keys_t *wickr_encoder_keys_gen_default_random(wickr_crypto_engine_t engine);
    
#ifdef __cplusplus
}
#endif

#endif /* encoder_keys_h */
