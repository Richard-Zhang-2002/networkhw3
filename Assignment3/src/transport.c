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


enum
{
    CSTATE_ESTABLISHED,
    CSTATE_WAITING_FOR_FINACK_PASSIVE,
    CSTATE_WAITING_FOR_FINACK_ACTIVE,
    CSTATE_WAITING_FOR_FIN_ACTIVE,
};   /* obviously you should have more states */


/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;
    tcp_seq next_seq_to_send;
    bool_t active;
    /* any other connection-wide global variables go here */
} context_t;


static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);

void socket_be_closed_handler(mysocket_t sd, context_t *ctx);

//send syn packet for connection
unsigned int send_syn_handshake (mysocket_t sd, context_t *ctx)
{
    printf("Handshake: sendng syn packet...\n");
    STCPHeader syn_packet = {0};
    syn_packet.th_flags = TH_SYN;
    syn_packet.th_seq = ctx->initial_sequence_num;
    if (stcp_network_send(sd, &syn_packet, sizeof(syn_packet), NULL) == -1){//syn send failed
        perror("Failed to send SYN");
        errno = ECONNREFUSED;
        return 0;
    }
    ctx->next_seq_to_send++;  // update next_seq_to_send
    printf("Syn packet sent sucess. c_seq=%u\n",syn_packet.th_seq);
    return 1;
}

unsigned int waitfor_syn_handshake (mysocket_t sd, context_t *ctx, STCPHeader* syn_packet )
{
    printf("Handshake: wait for the syn packet...\n");
    while (1){
        ssize_t bytes_received = stcp_network_recv(sd, syn_packet, sizeof(STCPHeader));
        if (bytes_received == -1){
            perror("Failed to receive SYN");
            errno = ECONNREFUSED;
            return 0;
        }

        if ((syn_packet->th_flags & (TH_SYN)) == (TH_SYN)){
            break;
        }
    }
    printf("Received the syn packet success. c_seq=%u\n", syn_packet->th_seq);
    return 1;
}

//send syn-ack for handshake
unsigned int sent_syn_ack_handshake(mysocket_t sd, context_t* ctx, STCPHeader* syn_packet)
{
    printf("Hankshake: sendng syn_ack packet...\n");
    STCPHeader syn_ack_packet = {0};
    syn_ack_packet.th_flags = TH_SYN | TH_ACK;
    syn_ack_packet.th_seq = ctx->initial_sequence_num;
    syn_ack_packet.th_ack = syn_packet->th_seq + 1;

    if (stcp_network_send(sd, &syn_ack_packet, sizeof(STCPHeader), NULL) == -1){//syn ack send failed
        perror("Failed to send SYN ACK");
        return 0;
    }

    ctx->next_seq_to_send++;
    printf("Sent syn-act packet success. s_seq=%u, s_ack=%u\n",
            syn_ack_packet.th_seq, syn_ack_packet.th_ack );
    return 1;
}

//wait for syn-ack
unsigned int waitfor_syn_ack_handshake(mysocket_t sd, context_t* ctx, STCPHeader* syn_ack_packet)
{
    printf("Handshake: waiting for syn_ack packet...\n");
    while(1) {
        ssize_t bytes_received = stcp_network_recv(sd, syn_ack_packet, sizeof(STCPHeader));
        if (bytes_received == -1){
            perror("Failed to receive SYN ACK");
            errno = ECONNREFUSED;
            return 0;
        }
        //if receive sys-ack
        if ((syn_ack_packet->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)){//syn ack is essentially joining the two
            if(syn_ack_packet->th_ack == ctx->next_seq_to_send)
                break;
        }
    }
    printf("Received syn-ack success. s_seq=%u, s_ack=%u\n",
        syn_ack_packet->th_seq,syn_ack_packet->th_ack);
    return 1;
}

//send ack for handshake
unsigned int send_ack_handshake(mysocket_t sd, context_t* ctx, STCPHeader* syn_ack_packet)
{
    printf("Handshake: sendinging ack...\n");
    STCPHeader ack_packet = {0};
    ack_packet.th_flags = TH_ACK;//just use normal ack this time

    ack_packet.th_seq = ctx->next_seq_to_send;
    ack_packet.th_ack = syn_ack_packet->th_seq + 1;//next expected number

    //if send failed
    if (stcp_network_send(sd, &ack_packet, sizeof(STCPHeader), NULL) == -1){
        perror("Failed to send ACK");
        errno = ECONNREFUSED;
        return 0;
    }

    //don't update ctx->next_seq_to_send since not consume sequence number this time

    printf("Sending ack success. c_seq=%u, c_ack=%u\n",
        ack_packet.th_seq, ack_packet.th_ack);
    return 1;

}

//wait for normal ack
unsigned int waitfor_ack_handshake(mysocket_t sd, context_t* ctx, STCPHeader* ack_packet)
{
    printf("Handshake: waiting for ack packet...\n");
    while(1) {
        ssize_t bytes_received = stcp_network_recv(sd, ack_packet, sizeof(STCPHeader));
        if (bytes_received == -1){
            perror("Failed to receive ACK");
            return 0;
        }

        if ((ack_packet->th_flags & (TH_ACK)) == (TH_ACK)){
            if(ack_packet->th_ack == ctx->next_seq_to_send) {
                break;
            }
        }
    }

    printf("Received ack packet success. c_seq=%u, c_ack=%u\n",
        ack_packet->th_seq, ack_packet->th_ack);

    return 1;
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
    ctx->active = is_active;//save whether we are handling active or passive link here

    if (is_active) {
        printf("active-shake\n");

        STCPHeader syn_ack_packet;

        if( send_syn_handshake(sd, ctx) == 0  ||
            waitfor_syn_ack_handshake(sd, ctx, &syn_ack_packet) == 0 ||
            send_ack_handshake(sd, ctx, &syn_ack_packet) == 0)
            return;
        printf("active-shake end\n");

    } else {
        printf("passive-shake\n");
        STCPHeader syn_packet;
        STCPHeader ack_packet;

        if( waitfor_syn_handshake(sd, ctx, &syn_packet) == 0 ||
            sent_syn_ack_handshake(sd, ctx, &syn_packet) == 0 ||
            waitfor_ack_handshake(sd, ctx, &ack_packet) == 0 )
            return;
        printf("passive-shake end\n");
    }

    ctx->connection_state = CSTATE_ESTABLISHED;
    stcp_unblock_application(sd);
    printf("CSTATE_ESTABLISHED\n");

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

/* handler for received message from stcp peer*/
void incoming_data_from_peer_handler(mysocket_t sd, context_t *ctx)
{
    printf("NETWORK_DATA: receive data from STCP peer.\n");

    char buffer[1024];
    ssize_t bytes_received = stcp_network_recv(sd, buffer, sizeof(buffer));
    if (bytes_received == -1){
        perror("Failed to receive message.");
        return;
    }

    if (bytes_received > 0)
    {//similarly, if received from peer, send to app
        STCPHeader *header = (STCPHeader *)buffer;
        char *data = buffer + sizeof(STCPHeader);
        ssize_t data_bytes = bytes_received - sizeof(STCPHeader);

        // display the type of packet
        printf("Flags set: ");
        if (header->th_flags & TH_FIN) printf("FIN ");
        if (header->th_flags & TH_SYN) printf("SYN ");
        if (header->th_flags & TH_RST) printf("RST ");
        if (header->th_flags & TH_PUSH) printf("PUSH ");
        if (header->th_flags & TH_ACK) printf("ACK ");
        if (header->th_flags & TH_URG) printf("URG ");
        printf("\n");

        // send received data to app (filename is rcvd)
        if (data_bytes > 0){
            stcp_app_send(sd, data, data_bytes);
        }

        // calculate the ack sequence number
        tcp_seq ack_seq = (data_bytes > 0) ? (header->th_seq + data_bytes):(header->th_seq + 1);

        // handle different type of received packet

        if ((header->th_flags & TH_FIN))  //if we are suppose to terminate (passive)
        {
            /* Four steps to terminate STCP connnection passive
             * step1: receive fin
             * step2: send ack
             * step3: send fin
             * step4: receive ack
             */
            printf("step1: received fin, seq=%u\n",header->th_seq) ;

            ctx->connection_state = CSTATE_WAITING_FOR_FINACK_PASSIVE;

            printf("step2: send fin-ack, ");
            STCPHeader ack_packet = {0};
            ack_packet.th_flags = TH_ACK;
            ack_packet.th_seq = ctx->next_seq_to_send;
            ack_packet.th_ack = ack_seq;
            ack_packet.th_off = 5;
            if (stcp_network_send(sd, &ack_packet, sizeof(ack_packet), NULL) == -1){
                perror("Failed to send ACK for FIN");
                return;
            }
            printf("seq=%u, ack=%u\n",ack_packet.th_seq,ack_packet.th_ack) ;

            printf("step3: send fin, ");
            STCPHeader fin_packet = {0};
            fin_packet.th_flags = TH_FIN;
            fin_packet.th_seq = ctx->next_seq_to_send;
            fin_packet.th_ack = ack_seq;
            fin_packet.th_off = 5;
            if (stcp_network_send(sd, &fin_packet, sizeof(fin_packet), NULL) == -1){
                perror("Failed to send FIN");
                return;
            }
            ctx->next_seq_to_send++;
            printf("seq=%u, ack=%u\n",fin_packet.th_seq,fin_packet.th_ack) ;

            printf("step4: receive fin ack, ");
            while(1) {//do not receive any message, just wait for that particular ack
                STCPHeader ack_packet = {0};
                ssize_t bytes_received = stcp_network_recv(sd, &ack_packet, sizeof(STCPHeader));
                if (bytes_received == -1){
                    perror("Failed to receive ACK.");
                    return;
                }

                if ((ack_packet.th_flags & (TH_ACK)) == (TH_ACK)){
                    if(ack_packet.th_ack == ctx->next_seq_to_send) {
                        printf("seq=%u, ack=%u\n",ack_packet.th_seq,ack_packet.th_ack) ;
                        break;
                    }
                }
            }

            printf("disconnect\n");
            ctx->done = 1;
            stcp_fin_received(sd);
        }
        else if ((header->th_flags & TH_ACK))
        {
            if(ctx->connection_state == CSTATE_WAITING_FOR_FINACK_ACTIVE)
            {
                /* Four steps to terminate STCP connnection active
                 * step1: send fin
                 * step2: receive ack
                 * step3: receive fin
                 * step4: send ack
                 */
                //for the active one, it sends fin, get ack,
                // now it should be expecting a fin from the other side
                if(header->th_ack == ctx->next_seq_to_send)
                    printf("step2: receive fin ack, seq=%u, ack=%u\n", header->th_seq, header->th_ack);

                printf("step3: receive fin,");
                STCPHeader fin_packet = {0};
                while(1) {

                    ssize_t bytes_received = stcp_network_recv(sd, &fin_packet, sizeof(STCPHeader));
                    if (bytes_received == -1){
                        perror("Failed to receive ACK.");
                        return;
                    }

                    if ((fin_packet.th_flags & (TH_FIN)) == (TH_FIN)){
                        if(fin_packet.th_ack == ctx->next_seq_to_send) {
                            printf(" seq=%u, ack=%u\n", fin_packet.th_seq, fin_packet.th_ack);
                            break;
                        }
                    }
                }

                printf("step4: sent fin ack, ");
                STCPHeader fin_ack_packet = {0};
                fin_ack_packet.th_flags = TH_ACK;
                fin_ack_packet.th_seq = ctx->next_seq_to_send;
                fin_ack_packet.th_ack = fin_packet.th_seq + 1;
                fin_ack_packet.th_off = 5;
                if (stcp_network_send(sd, &fin_ack_packet, sizeof(STCPHeader), NULL) == -1){
                    perror("Failed to send ACK for FIN");
                    return;
                }
                printf("seq=%u, ack=%u\n", fin_ack_packet.th_seq, fin_ack_packet.th_ack);

                printf("disconnect\n");
                ctx->done = 1;
                stcp_fin_received(sd);
            }
        }

        //otherwise if the header is not ack, send ack
        else
        {
            STCPHeader ack_packet = {0};
            ack_packet.th_flags = TH_ACK;
            ack_packet.th_seq = ctx->next_seq_to_send;
            ack_packet.th_ack = ack_seq;
            ack_packet.th_off = 5;

            if (stcp_network_send(sd, &ack_packet, sizeof(ack_packet), NULL) == -1)
            {
                perror("Failed to send ACK");
                return;
            }
            printf("Send ack: seq=%u, ack=%u\n", ack_packet.th_seq, ack_packet.th_ack);
            fflush(stdout);
            // no need for update ctx->next_seq_to_send since ack without payload
        }
    }
}

// try to send message
void new_data_from_application_handler(mysocket_t sd, context_t *ctx)
{
    printf("APP_DATA: try to send message to peer...\n");
    if(ctx->connection_state != CSTATE_ESTABLISHED){
        return;//if we are closing the connection, we won't be sending anything anymore
    }

    /* the application has requested that data be sent */
    /* see stcp_app_recv() */
    char buffer[STCP_MSS];
    ssize_t bytes_read;

    if ((bytes_read = stcp_app_recv(sd, buffer, STCP_MSS)) > 0){//cut large chunk of data into smaller packets
        printf("Bytes read from app: %zd\n", bytes_read);

        STCPHeader data_packet = {0};
        data_packet.th_seq = ctx->next_seq_to_send;

        //put the header and packet together
        char send_buffer[sizeof(STCPHeader) + bytes_read];
        memcpy(send_buffer, &data_packet, sizeof(STCPHeader));
        memcpy(send_buffer + sizeof(STCPHeader), buffer, bytes_read);

        while (1)
        {
            if (stcp_network_send(sd, send_buffer, sizeof(send_buffer), NULL) == -1){
                perror("Failed to send data");
                return;
            }

            printf("Sending packet: seq=%u, payload_size=%zd\n", data_packet.th_seq, bytes_read);
            tcp_seq next_seq = ctx->next_seq_to_send + bytes_read;
            ctx->next_seq_to_send = next_seq;

        }

    }

    printf("Sent message success. \n");
}

void socket_be_closed_handler(mysocket_t sd, context_t *ctx)
{
    printf("APP_CLOSE_REQUESTED\n");

    STCPHeader fin_packet = {0};
    fin_packet.th_flags = TH_FIN;
    fin_packet.th_seq = ctx->next_seq_to_send;
    fin_packet.th_off = 5;

    if (stcp_network_send(sd, &fin_packet, sizeof(STCPHeader), NULL) == -1){
        perror("Failed to send FIN");
        return;
    }

    ctx->next_seq_to_send++;
    ctx->connection_state = CSTATE_WAITING_FOR_FINACK_ACTIVE;
    //now we sent the fin, wait for the other side's response
    printf("Step1: sent fin, seq=%u\n", fin_packet.th_seq);
}

void timeout_handler(mysocket_t sd, context_t *ctx)
{

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

        //printf("prior wait event\n");
        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);
        //printf("post wait event\n");

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
            new_data_from_application_handler(sd, ctx);  // send general message
        else if (event & NETWORK_DATA)
            incoming_data_from_peer_handler(sd, ctx);    // receive general message
        else if (event & APP_CLOSE_REQUESTED)
            socket_be_closed_handler(sd, ctx);           // receive close request
        else{
            printf("ELSE!!!\n");
        }
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



