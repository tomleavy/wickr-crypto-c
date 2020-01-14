//
//  transport_handshake.c
//  wickrcrypto
//
//  Created by Tom Leavy on 1/14/20.
//

#include "transport_handshake.h"
#include "memory.h"
#include "private/transport_priv.h"

struct wickr_transport_handshake_res_t {
    wickr_stream_key_t *local_key;
    wickr_stream_key_t *remote_key;
};

wickr_transport_handshake_res_t *wickr_transport_handshake_res_create(wickr_stream_key_t *local_key,
                                                                      wickr_stream_key_t *remote_key)
{
    if (!local_key || !remote_key) {
        return NULL;
    }
    
    wickr_transport_handshake_res_t *result = wickr_alloc_zero(sizeof(wickr_transport_handshake_res_t));
    
    if (!result) {
        return NULL;
    }
    
    result->local_key = local_key;
    result->remote_key = remote_key;
    
    return result;
}

wickr_transport_handshake_res_t *wickr_transport_handshake_res_copy(const wickr_transport_handshake_res_t *res)
{
    wickr_stream_key_t *local_copy = wickr_stream_key_copy(res->local_key);
    wickr_stream_key_t *remote_copy = wickr_stream_key_copy(res->remote_key);
    
    if (!local_copy || !remote_copy) {
        wickr_stream_key_destroy(&local_copy);
        wickr_stream_key_destroy(&remote_copy);
        return NULL;
    }
    
    wickr_transport_handshake_res_t *copy = wickr_transport_handshake_res_create(local_copy, remote_copy);
    
    if (!copy) {
        wickr_stream_key_destroy(&local_copy);
        wickr_stream_key_destroy(&remote_copy);
    }
    
    return copy;
}

void wickr_transport_handshake_res_destroy(wickr_transport_handshake_res_t **res)
{
    if (!res || !*res) {
        return;
    }
    
    wickr_stream_key_destroy(&(*res)->local_key);
    wickr_stream_key_destroy(&(*res)->remote_key);
    
    wickr_free(*res);
    *res = NULL;
}

const wickr_stream_key_t *wickr_transport_handshake_get_local_key(const wickr_transport_handshake_res_t *handshake)
{
    return handshake->local_key;
}

const wickr_stream_key_t *wickr_transport_handshake_get_remote_key(const wickr_transport_handshake_res_t *handshake)
{
    return handshake->remote_key;
}

struct wickr_transport_handshake_t {
    wickr_identity_chain_t *local_identity;
    wickr_identity_chain_t *remote_identity;
    wickr_array_t *packet_list;
    wickr_transport_handshake_identity_callback identity_callback;
    wickr_transport_handshake_status status;
};

static wickr_transport_handshake_t *__wickr_transport_handshake_create(wickr_identity_chain_t *local_identity,
                                                                       wickr_identity_chain_t *remote_identity,
                                                                       wickr_array_t *packet_list,
                                                                       wickr_transport_handshake_identity_callback identity_callback)
{
    if (!local_identity || identity_callback == 0 || !packet_list) {
        return NULL;
    }
    
    wickr_transport_handshake_t *handshake = wickr_alloc_zero(sizeof(wickr_transport_handshake_t));
    
    if (!handshake) {
        wickr_array_destroy(&packet_list, true);
        return NULL;
    }
    
    handshake->local_identity = local_identity;
    handshake->remote_identity = remote_identity;
    handshake->identity_callback = identity_callback;
    handshake->packet_list = packet_list;
    handshake->status = TRANSPORT_HANDSHAKE_STATUS_UNKNOWN;
    
    return handshake;
}

wickr_transport_handshake_t *wickr_transport_handshake_create(wickr_identity_chain_t *local_identity,
                                                              wickr_identity_chain_t *remote_identity,
                                                              wickr_transport_handshake_identity_callback identity_callback)
{
    wickr_array_t *packet_list = wickr_array_new(2,
                                                 0,
                                                 (wickr_array_copy_func)wickr_transport_packet_copy,
                                                 (wickr_array_destroy_func)wickr_transport_packet_destroy);
    
    if (!packet_list) {
        return NULL;
    }
    
    return __wickr_transport_handshake_create(local_identity, remote_identity, packet_list, identity_callback);
}

wickr_transport_handshake_t *wickr_transport_handshake_copy(const wickr_transport_handshake_t *handshake)
{
    if (!handshake) {
        return NULL;
    }
    
    wickr_identity_chain_t *local_copy = wickr_identity_chain_copy(handshake->local_identity);
    wickr_identity_chain_t *remote_copy = wickr_identity_chain_copy(handshake->remote_identity);
    wickr_array_t *packet_list_copy = wickr_array_copy(handshake->packet_list, true);
    
    if (!local_copy ||
        (!remote_copy && handshake->remote_identity) ||
        !packet_list_copy) {
        wickr_identity_chain_destroy(&local_copy);
        wickr_identity_chain_destroy(&remote_copy);
        wickr_array_destroy(&packet_list_copy, true);
    }
    
    wickr_transport_handshake_t *copy = __wickr_transport_handshake_create(local_copy, remote_copy, packet_list_copy, handshake->identity_callback);
    
    if (!copy) {
        wickr_identity_chain_destroy(&local_copy);
        wickr_identity_chain_destroy(&remote_copy);
        wickr_array_destroy(&packet_list_copy, true);
    }
    
    copy->status = handshake->status;
    return copy;
}

void wickr_transport_handshake_destroy(wickr_transport_handshake_t **handshake)
{
    if (!handshake || !*handshake) {
        return;
    }
    
    wickr_identity_chain_destroy(&(*handshake)->local_identity);
    wickr_identity_chain_destroy(&(*handshake)->remote_identity);
    wickr_array_destroy(&(*handshake)->packet_list, true);
    
    wickr_free(*handshake);
    *handshake = NULL;
}

wickr_buffer_t *wickr_transport_handshake_process(wickr_transport_handshake_t *handshake, const wickr_buffer_t *buffer)
{
    //TODO: The actual handshake
}

wickr_transport_handshake_res_t *wickr_transport_handshake_finalize(const wickr_transport_handshake_t *handshake)
{
    //TODO: Finalize handshake data into keys
}

const wickr_transport_handshake_status wickr_transport_handshake_get_status(const wickr_transport_handshake_t *handshake)
{
    return handshake->status;
}

const wickr_identity_chain_t *wickr_transport_handshake_get_local_identity(const wickr_transport_handshake_t *handshake)
{
    return handshake->local_identity;
}

const wickr_identity_chain_t *wickr_transport_handshake_get_remote_identity(const wickr_transport_handshake_t *handshake)
{
    return handshake->remote_identity;
}
