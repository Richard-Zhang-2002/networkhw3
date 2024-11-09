#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"

enum {
    CSTATE_CLOSED,
    CSTATE_LISTEN,
    CSTATE_SYN_SENT,
    CSTATE_SYN_RECEIVED,
    CSTATE_ESTABLISHED,
    CSTATE_FIN_WAIT_1,
    CSTATE_FIN_WAIT_2,
    CSTATE_CLOSE_WAIT,
    CSTATE_CLOSING,
    CSTATE_LAST_ACK,
    CSTATE_TIME_WAIT
};

typedef struct {
    bool_t done;
    int connection_state;
    tcp_seq initial_sequence_num;
    tcp_seq next_expected_seq;
    tcp_seq last_ack_sent;
    tcp_seq send_base;  // sequence number of the first byte in the window
} context_t;

static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
static void send_syn_packet(mysocket_t sd, context_t *ctx);
static void receive_syn_ack(mysocket_t sd, context_t *ctx);
static void send_ack_packet(mysocket_t sd, context_t *ctx, tcp_seq ack_num);
static void handle_app_data(mysocket_t sd, context_t *ctx);
static void handle_network_data(mysocket_t sd, context_t *ctx);

void transport_init(mysocket_t sd, bool_t is_active) {
    context_t *ctx = (context_t *)calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);
    ctx->connection_state = CSTATE_CLOSED;

    if (is_active) {
        ctx->connection_state = CSTATE_SYN_SENT;
        send_syn_packet(sd, ctx);
        // Wait for SYN-ACK handled in control loop
    } else {
        ctx->connection_state = CSTATE_LISTEN;
    }

    control_loop(sd, ctx);
    free(ctx);
}

static void generate_initial_seq_num(context_t *ctx) {
    assert(ctx);
    ctx->initial_sequence_num = rand() % 256;
}

static void control_loop(mysocket_t sd, context_t *ctx) {
    assert(ctx);
    while (!ctx->done) {
        unsigned int event = stcp_wait_for_event(sd, ANY_EVENT, NULL);
        
        switch (ctx->connection_state) {
            case CSTATE_SYN_SENT:
                receive_syn_ack(sd, ctx);
                break;
            case CSTATE_ESTABLISHED:
                if (event & APP_DATA) {
                    handle_app_data(sd, ctx);
                }
                if (event & NETWORK_DATA) {
                    handle_network_data(sd, ctx);
                }
                break;
            case CSTATE_LISTEN:
                // Implement passive open behavior here
                break;
        }
        
        if (event & APP_CLOSE_REQUESTED) {
            ctx->done = TRUE; // Add proper closure handling later
        }
    }
}

void send_syn_packet(mysocket_t sd, context_t *ctx) {
    STCPHeader syn_header;
    memset(&syn_header, 0, sizeof(STCPHeader));
    syn_header.th_seq = ctx->initial_sequence_num;
    syn_header.th_flags = TH_SYN;
    stcp_network_send(sd, &syn_header, sizeof(syn_header), NULL);
}

void receive_syn_ack(mysocket_t sd, context_t *ctx) {
    STCPHeader syn_ack_header;
    size_t header_size = sizeof(syn_ack_header);
    if (stcp_network_recv(sd, &syn_ack_header, header_size) > 0) {
        if (syn_ack_header.th_flags & TH_ACK) {
            ctx->next_expected_seq = syn_ack_header.th_ack;
            ctx->connection_state = CSTATE_ESTABLISHED;
            send_ack_packet(sd, ctx, ctx->next_expected_seq);
        }
    }
}

void send_ack_packet(mysocket_t sd, context_t *ctx, tcp_seq ack_num) {
    STCPHeader ack_header;
    memset(&ack_header, 0, sizeof(STCPHeader));
    ack_header.th_flags = TH_ACK;
    ack_header.th_ack = ack_num;
    stcp_network_send(sd, &ack_header, sizeof(ack_header), NULL);
}

void handle_app_data(mysocket_t sd, context_t *ctx) {
    char buffer[STCP_MSS];
    ssize_t bytes_read = stcp_app_recv(sd, buffer, STCP_MSS);
    if (bytes_read > 0) {
        STCPHeader data_header;
        memset(&data_header, 0, sizeof(STCPHeader));
        data_header.th_seq = ctx->next_expected_seq;
        data_header.th_flags = 0; // No flag for regular data packets
        stcp_network_send(sd, &data_header, sizeof(data_header), buffer, bytes_read, NULL);
        ctx->next_expected_seq += bytes_read;
    }
}

void handle_network_data(mysocket_t sd, context_t *ctx) {
    STCPHeader header;
    char data[STCP_MSS];
    ssize_t received_size = stcp_network_recv(sd, &header, sizeof(header), data, STCP_MSS, NULL);
    if (received_size > 0 && (header.th_flags & TH_ACK)) {
        // Process the acknowledgment
        ctx->send_base = header.th_ack;
    }
}
