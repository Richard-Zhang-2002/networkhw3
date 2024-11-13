/*
 * transport.c 
 *
 * EN.601.414/614: HW#3 (STCP)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"
#include <time.h>
#include <arpa/inet.h>


#define FIN_TIMEOUT 2 


enum
{
    CSTATE_ESTABLISHED,
    CSTATE_WAITING_FOR_FINACK_PASSIVE,
    CSTATE_WAITING_FOR_FINACK_ACTIVE,
    CSTATE_WAITING_FOR_FIN_ACTIVE,
};   /* obviously you should have more states */


typedef struct queue_node {
    char *data;
    ssize_t size;
    struct queue_node *next;
} queue_node_t;

typedef struct {
    queue_node_t *head;
    queue_node_t *tail;
} queue_t;

void enqueue(queue_t *queue, char *data, ssize_t size) {
    queue_node_t *new_node = (queue_node_t *)malloc(sizeof(queue_node_t));
    new_node->data = data;
    new_node->size = size;
    new_node->next = NULL;

    if (queue->tail) {
        queue->tail->next = new_node;
    } else {
        queue->head = new_node;
    }
    queue->tail = new_node;
}

void dequeue(queue_t *queue) {
    if (!queue->head) return;

    queue_node_t *temp = queue->head;
    queue->head = queue->head->next;

    if (!queue->head) queue->tail = NULL;

    free(temp->data);
    free(temp);
}


/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;
    tcp_seq next_seq_to_send;
    tcp_seq last_ack_received;
    bool_t active;
    time_t fin_sent_time;
    queue_t data_queue;
    /* any other connection-wide global variables go here */
} context_t;


static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);


/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */

    ctx->next_seq_to_send = ctx->initial_sequence_num;//initialization
    ctx->active = is_active;//save whether we are handling active or passive link here

    if (is_active) {
        printf("active-shake\n");

        // send syn packet
        STCPHeader syn_packet = {0};
        syn_packet.th_flags = TH_SYN;
        syn_packet.th_seq = htonl(ctx->next_seq_to_send);
        if (stcp_network_send(sd, &syn_packet, sizeof(syn_packet), NULL) == -1){//syn send failed
            perror("Failed to send SYN");
            errno = ECONNREFUSED;
            return;
        }
        ctx->next_seq_to_send++;

        // wait for syn ack
        STCPHeader syn_ack_packet;
        while (1){
            ssize_t bytes_received = stcp_network_recv(sd, &syn_ack_packet, sizeof(syn_ack_packet));
            if (bytes_received == -1){
                perror("Failed to receive SYN ACK");
                errno = ECONNREFUSED;
                return;
            }
            tcp_seq local_ack_num = ntohl(syn_ack_packet.th_ack);
            //if ack exists
            if ((syn_ack_packet.th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK) && tcp_seq local_ack_num == ctx->next_seq_to_send){//syn ack is essentially joining the two
                printf("syn_ack_packet.th_ack: %u\n", syn_ack_packet.th_ack);
                printf("ctx->next_seq_to_send: %u\n", ctx->next_seq_to_send);
                break;
            }
        }

        // send ack
        STCPHeader ack_packet = {0};
        ack_packet.th_flags = TH_ACK;//just use normal ack this time
        ack_packet.th_seq = ctx->next_seq_to_send;//the sequence number(+1 since ack and syn here takes 1 even if no payload exists)
        ack_packet.th_ack = syn_ack_packet.th_seq + 1;//next expected number
        //if send failed
        if (stcp_network_send(sd, &ack_packet, sizeof(ack_packet), NULL) == -1){
            perror("Failed to send ACK");
            errno = ECONNREFUSED;
            return;
        }
        ctx->next_seq_to_send++;
        printf("active-shake-end\n");

    } else {
        printf("passive-shake\n");
        // wait for syn
        STCPHeader syn_packet;
        while (1){
            ssize_t bytes_received = stcp_network_recv(sd, &syn_packet, sizeof(syn_packet));
            if (bytes_received == -1){
                perror("Failed to receive SYN");
                errno = ECONNREFUSED;
                return;
            }
            //if ack exists
            if ((syn_packet.th_flags & (TH_SYN)) == (TH_SYN)){
                break;
            }
        }

        // send syn ack
        STCPHeader syn_ack_packet = {0};
        syn_ack_packet.th_flags = TH_SYN | TH_ACK;
        syn_ack_packet.th_seq = ctx->next_seq_to_send;
        syn_ack_packet.th_ack = syn_packet.th_seq + 1;
        if (stcp_network_send(sd, &syn_ack_packet, sizeof(syn_ack_packet), NULL) == -1){//syn ack send failed
            perror("Failed to send SYN ACK");
            return;
        }
        ctx->next_seq_to_send++;

        // wait for ack
        STCPHeader ack_packet;
        while (1){
            ssize_t bytes_received = stcp_network_recv(sd, &ack_packet, sizeof(ack_packet));
            if (bytes_received == -1){
                perror("Failed to receive ACK");
                return;
            }
            //if ack exists
            if ((ack_packet.th_flags & (TH_ACK)) == (TH_ACK) && ack_packet.th_ack == ctx->next_seq_to_send){
                break;
            }
        }
        printf("passive-shake-end\n");
    }
    ctx->connection_state = CSTATE_ESTABLISHED;
    stcp_unblock_application(sd);

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* you have to fill this up */
    ctx->initial_sequence_num = rand() % 256; //result from 0 to 255 inclusive
#endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    return;
}


/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}



