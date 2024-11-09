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


enum { 
    CSTATE_ESTABLISHED,//ordinary connection, both are running normally
    CSTATE_FINWAIT_1,//this context already send fin(as active), the other side haven't. Is waiting for ack
    CSTATE_FINWAIT_2,//this context already send fin(as active), the other side haven't. Got an ack, waiting for fin
    CSTATE_FIN_RECEIVE,//this context received a fin and responded with an ack, now it simply waits for transmission to finish and send send fin
};  /* obviously you should have more states */



/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;

    //for sender windows
    tcp_seq next_seq_to_send;
    tcp_seq last_ack_received;

    //for receiver windows
    tcp_seq next_expected_seq;

    size_t max_window_size;
} context_t;


static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);

//send an ack, helper function
void send_ack(mysocket_t sd, context_t *ctx, tcp_seq ack_num) {
    STCPHeader ack_packet = {0};
    ack_packet.th_flags = TH_ACK;
    ack_packet.th_seq = ctx->next_seq_to_send;
    ack_packet.th_ack = ack_num;
    ack_packet.th_off = 5;

    if (stcp_network_send(sd, &ack_packet, sizeof(ack_packet), NULL) == -1) {
        perror("Failed to send ACK");
    }
}

// send a fin, helper function
void send_fin(mysocket_t sd, context_t *ctx) {
    STCPHeader fin_packet = {0};
    fin_packet.th_flags = TH_FIN;
    fin_packet.th_seq = ctx->next_seq_to_send;
    fin_packet.th_off = 5;

    if (stcp_network_send(sd, &fin_packet, sizeof(fin_packet), NULL) == -1) {
        perror("Failed to send FIN");
    }else{
        ctx->next_seq_to_send += 1;
    }
}



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
    ctx->last_ack_received = ctx->initial_sequence_num;
    ctx->next_expected_seq = -1;//psudo value, will be replaced once the first input arrives
    ctx->max_window_size = 3072;

    if (is_active) {

        // send syn packet
        STCPHeader syn_packet = {0};
        syn_packet.th_flags = TH_SYN;
        syn_packet.th_seq = ctx->initial_sequence_num;
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
            //if ack exists
            if ((syn_ack_packet.th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)){//syn ack is essentially joining the two
                break;
            }
        }

        // send ack
        STCPHeader ack_packet = {0};
        ack_packet.th_flags = TH_ACK;//just use normal ack this time
        ack_packet.th_seq = syn_packet.th_seq + 1;//the sequence number(+1 since ack and syn here takes 1 even if no payload exists)
        ack_packet.th_ack = syn_ack_packet.th_seq + 1;//next expected number
        //if send failed
        if (stcp_network_send(sd, &ack_packet, sizeof(ack_packet), NULL) == -1){
            perror("Failed to send ACK");
            errno = ECONNREFUSED;
            return;
        }

    } else {
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
        syn_ack_packet.th_seq = ctx->initial_sequence_num;
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
            if ((ack_packet.th_flags & (TH_ACK)) == (TH_ACK)){
                break;
            }
        }
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
    assert(ctx);

    while (!ctx->done)
    {
        unsigned int event;

        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
        {
            printf("app data\n");
            if (ctx->connection_state != CSTATE_ESTABLISHED && ctx->connection_state != CSTATE_FIN_RECEIVE){
                continue;//we should only be listening
            }
            char buffer[STCP_MSS];
            ssize_t payload_size;
            if ((payload_size = stcp_app_recv(sd, buffer, STCP_MSS)) > 0){
                tcp_seq window_start = ctx->last_ack_received;
                tcp_seq window_end = window_start + ctx->max_window_size;

                while(window_end < ctx->next_seq_to_send + payload_size){//wait until there is spot in the window
                    continue;
                }
                //there is window, now send
                STCPHeader data_packet = {0};
                data_packet.th_seq = ctx->next_seq_to_send;
                data_packet.th_off = 5;
                data_packet.th_flags = 0;

                //put header with packet
                char send_buffer[sizeof(STCPHeader) + payload_size];
                memcpy(send_buffer, &data_packet, sizeof(STCPHeader));
                memcpy(send_buffer + sizeof(STCPHeader), buffer, payload_size);

                if (stcp_network_send(sd, send_buffer, sizeof(send_buffer), NULL) == -1){
                    perror("Failed to send data packet");
                    return;
                }
                // Update the next sequence number and window tracking
                ctx->next_seq_to_send += payload_size;
                printf("payload sent\n");
            }

        }

        if (event & NETWORK_DATA) {
            printf("network data\n");
            /* received data from STCP peer */
            char buffer[1024];
            ssize_t bytes_received = stcp_network_recv(sd, buffer, sizeof(buffer));
            if (bytes_received > 0){
                STCPHeader *header = (STCPHeader *)buffer;
                char *data = buffer + sizeof(STCPHeader);
                ssize_t data_bytes = bytes_received - sizeof(STCPHeader);

                tcp_seq next_expected_seq = (data_bytes > 0) ? (header->th_seq + data_bytes):(header->th_seq + 1);
                ctx->next_expected_seq = next_expected_seq;
                if (header->th_flags & TH_ACK){//when we receive an ack
                    printf("ACK received\n");
                    ctx->last_ack_received = header->th_ack;
                    if(ctx->connection_state == CSTATE_FINWAIT_1){
                        if(header->th_ack >= ctx->next_seq_to_send){//basically this is the ack for our fin
                            ctx->connection_state = CSTATE_FINWAIT_2;//now we wait for their fin
                        }
                    }
                }

                if(header->th_flags & TH_FIN){//we receive a fin
                    printf("FIN received\n");
                    if (data_bytes <= 0){//prevent repetition of ack
                        send_ack(sd, ctx, next_expected_seq);//we send ack regardless
                    }
                    if(ctx->connection_state == CSTATE_FINWAIT_2){//meaning that we are already ready to close
                        ctx->done = true;
                        stcp_fin_received(sd);
                    }else if(ctx->connection_state == CSTATE_ESTABLISHED){
                        ctx->connection_state = CSTATE_FIN_RECEIVE;//just remember that the neighbor already fin
                    }
                }

                if (data_bytes > 0){//if there is any payload
                    char recv_buffer[STCP_MSS];
                    ssize_t received_size;
                    if ((received_size = stcp_network_recv(sd, recv_buffer, STCP_MSS)) > 0){
                        STCPHeader *header = (STCPHeader *)recv_buffer;
                        char *data = recv_buffer + sizeof(STCPHeader);
                        ssize_t payload_size = received_size - sizeof(STCPHeader);
                        tcp_seq seq_num = header->th_seq;

                        if (seq_num == ctx->next_expected_seq){//should be true since there is no packet loss in our example
                            stcp_app_send(sd, data, payload_size);
                        }
                        ctx->next_expected_seq += payload_size;
                        send_ack(sd, ctx, ctx->next_expected_seq);
                        printf("Received and acknowledged sequence %u\n", seq_num);
                    }
                }


            }


        }

        if (event & APP_CLOSE_REQUESTED) {
            printf("app close\n");

        }

        /* etc. */
    }
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
