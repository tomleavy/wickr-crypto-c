#ifndef externs_h
#define externs_h

#include "crypto_engine.h"
#include "wickr_ctx.h"

extern wickr_crypto_engine_t engine;
extern wickr_buffer_t *dev_salt;

extern void init_test();

extern wickr_identity_chain_t *create_identity_chain(char *user_name);
extern wickr_node_t *create_user_node(char *user_name, wickr_buffer_t *dev_id);
extern wickr_dev_info_t *create_dev_info(wickr_buffer_t *system_id);
extern wickr_buffer_t *create_device_identity(uint8_t *dev_str, size_t dev_len);
extern wickr_buffer_t *hex_char_to_buffer(const char *hex);
extern wickr_buffer_t *hex_char_to_buffer(const char *hex);
extern wickr_ctx_t *create_context(wickr_node_t *user_node);

#endif // externs_h
