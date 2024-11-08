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
    CSTATE_ESTABLISHED

};    /* obviously you should have more states */


/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;
    tcp_seq next_seq_to_send;
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

    if (is_active) {
        printf("active-shake\n");

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
            printf("sent\n");
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
            char buffer[STCP_MSS];
            ssize_t bytes_read = stcp_app_recv(sd, buffer, sizeof(buffer));
            if (bytes_read > 0){//if the app gives us something to send
                STCPHeader data_packet = {0};
                data_packet.th_seq = ctx->next_seq_to_send;

                //put the header and packet together
                char send_buffer[sizeof(STCPHeader) + bytes_read];
                memcpy(send_buffer, &data_packet, sizeof(STCPHeader));
                memcpy(send_buffer + sizeof(STCPHeader), buffer, bytes_read);

                if (stcp_network_send(sd, send_buffer, sizeof(send_buffer), NULL) == -1){
                    perror("Failed to send data");
                    return;
                }
                ctx->next_seq_to_send += bytes_read;
            }
            printf("sent-end\n");
        }

        if (event & NETWORK_DATA) {
            /* received data from STCP peer */
            char buffer[STCP_MSS];
            ssize_t bytes_received = stcp_network_recv(sd, buffer, sizeof(buffer));
            if (bytes_received > 0) {//similarly, if received from peer, send to app
                STCPHeader *header = (STCPHeader *)buffer;
                char *data = buffer + sizeof(STCPHeader);
                ssize_t data_bytes = bytes_received - sizeof(STCPHeader);

                //tell the other side about the next expected bit
                tcp_seq next_expected_seq = (data_bytes > 0) ? (header->th_seq + data_bytes):(header->th_seq + 1);

                if (header->th_flags & TH_FIN){//if we are suppose to terminate(passive)
                    printf("fin-received\n");
                    if (data_bytes > 0){//send to app regardless
                        stcp_app_send(sd, data, data_bytes);
                    }
                    STCPHeader ack_packet = {0};
                    ack_packet.th_flags = TH_ACK;
                    ack_packet.th_seq = ctx->next_seq_to_send;
                    ack_packet.th_ack = next_expected_seq;

                    if (stcp_network_send(sd, &ack_packet, sizeof(ack_packet), NULL) == -1){
                        perror("Failed to send ACK for FIN");
                        return;
                    }

                    //also send our own fin
                    STCPHeader fin_packet = {0};                
                    fin_packet.th_flags = TH_FIN;
                    fin_packet.th_seq = ctx->next_seq_to_send;

                    if (stcp_network_send(sd, &fin_packet, sizeof(fin_packet), NULL) == -1){
                        perror("Failed to send FIN");
                        return;
                    }
                    ctx->next_seq_to_send++;

                    //wait for the ack for our fin
                    STCPHeader final_ack_packet;
                    while (1){
                        ssize_t bytes_received = stcp_network_recv(sd, &final_ack_packet, sizeof(final_ack_packet));
                        if (bytes_received == -1){
                            perror("Failed to receive final ACK for our FIN");
                            return;
                        }

                        if (final_ack_packet.th_flags & TH_ACK) {
                            ctx->done = true;
                            stcp_fin_received(sd);
                            break;
                        }
                    }
                    printf("fin-received-end\n");
                }
                else if (data_bytes > 0){
                    printf("received\n");
                    stcp_app_send(sd, data, data_bytes);

                    STCPHeader ack_packet = {0};
                    ack_packet.th_flags = TH_ACK;
                    ack_packet.th_seq = ctx->next_seq_to_send;
                    ack_packet.th_ack = next_expected_seq;

                    if (stcp_network_send(sd, &ack_packet, sizeof(ack_packet), NULL) == -1){
                        perror("Failed to send ACK");
                        return;
                    }
                    printf("received-end\n");
                }

                
            }
        }

        if (event & APP_CLOSE_REQUESTED) {//do the handshake for termination
            printf("fin-sent\n");
            STCPHeader fin_packet = {0};
            fin_packet.th_flags = TH_FIN;
            fin_packet.th_seq = ctx->next_seq_to_send;

            if (stcp_network_send(sd, &fin_packet, sizeof(fin_packet), NULL) == -1){
                perror("Failed to send FIN");
                return;
            }
            ctx->next_seq_to_send++;

            STCPHeader ack_packet;
            while (1){//wait for ack
                ssize_t bytes_received = stcp_network_recv(sd, &ack_packet, sizeof(ack_packet));
                if (bytes_received == -1){
                    perror("Failed to receive ACK for FIN");
                    return;
                }
                if (ack_packet.th_flags & TH_ACK){//if ack is received
                    break;
                }
            }

            STCPHeader fin_ack_packet;
            while (1){//wait for the peer's fin
                ssize_t bytes_received = stcp_network_recv(sd, &fin_ack_packet, sizeof(fin_ack_packet));
                if (bytes_received == -1){
                    perror("Failed to receive peer's FIN");
                    return;
                }
                if (fin_ack_packet.th_flags & TH_FIN){//if we get the fin from peer, send an acknowledgement back
                    STCPHeader ack_packet = {0};
                    ack_packet.th_flags = TH_ACK;
                    ack_packet.th_seq = ctx->next_seq_to_send;
                    ack_packet.th_ack = fin_ack_packet.th_seq + 1;
                    if (stcp_network_send(sd, &ack_packet, sizeof(ack_packet), NULL) == -1){
                        perror("Failed to send ACK for peer's FIN");
                        return;
                    }
                    ctx->done = true;
                    stcp_fin_received(sd);
                    //no need to increment the next bit sent since the connection is over
                    break;
                }
            }
            printf("fin-sent-end\n");
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



