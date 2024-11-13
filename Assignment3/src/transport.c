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


#define MSL 1000   // use for time wait


enum
{
    CSTATE_ESTABLISHED,

    CSTATE_WAITING_FOR_FINACK_ACTIVE,
    CSTATE_WAITING_FOR_FIN_ACTIVE,
    CSTATE_TIME_WAIT_ACTIVE, // 2 MSL

    CSTATE_CLOSE_WAIT_PASSIVE,
    CSTATE_LAST_ACK_PASSIVE,


};   /* obviously you should have more states */


/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */

    tcp_seq initial_sequence_num;
    tcp_seq seq_num;
    tcp_seq next_seq_to_send;
    tcp_seq last_ack_received;
    bool_t active;
    time_t time_out;
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
        syn_packet.th_seq = ctx->next_seq_to_send;
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
            if ((syn_ack_packet.th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK))
            {//syn ack is essentially joining the two
             //   printf("syn_ack_packet.th_ack: %u\n", syn_ack_packet.th_ack);
             //   printf("ctx->next_seq_to_send: %u\n", ctx->next_seq_to_send);
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
        // ctx->next_seq_to_send++; //send ack will not update ctx->next_seq_to_send
        printf("active-shake-end, next_seq_to_send=%u\n",ctx->next_seq_to_send);

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

        // send syn-ack
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
        printf("passive-shake-end, next_seq_to_send=%u\n",ctx->next_seq_to_send);
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

        //printf("prior wait event\n");
        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);
        //printf("post wait event\n");

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
        {
            if(ctx->connection_state != CSTATE_ESTABLISHED){
                continue;//if we are closing the connection, we won't be sending anything anymore
            }

            //printf("APP_DATA: send start\n");
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
            char buffer[STCP_MSS];
            ssize_t bytes_read;
            if ((bytes_read = stcp_app_recv(sd, buffer, STCP_MSS)) > 0){//cut large chunk of data into smaller packets
                //printf("Bytes read from app: %zd\n", bytes_read);

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
                printf("APP_DATA: sent, seq=%u, payload=%zd, next_espect_seq=%u\n",
                    data_packet.th_seq, bytes_read, ctx->next_seq_to_send  );
            }
        } // event & APP_DATA

        if (event & NETWORK_DATA)
        {
            //printf("NETWORK_DATA: receive start\n");
            /* received data from STCP peer */
            char buffer[1024];
            ssize_t bytes_received = stcp_network_recv(sd, buffer, sizeof(buffer));
            if (bytes_received == -1){
                perror("Failed to receive data.");
                errno = ECONNREFUSED;
                return;
            }


            if (bytes_received > 0) {//similarly, if received from peer, send to app
                STCPHeader *header = (STCPHeader *)buffer;
                char *data = buffer + sizeof(STCPHeader);
                ssize_t data_bytes = bytes_received - sizeof(STCPHeader);
                //printf("Bytes received from network: %zd\n", data_bytes);

                printf("NETWORK_DATA: Received ");
                if (header->th_flags & TH_FIN) printf("FIN ");
                if (header->th_flags & TH_SYN) printf("SYN ");
                if (header->th_flags & TH_RST) printf("RST ");
                if (header->th_flags & TH_PUSH) printf("PUSH ");
                if (header->th_flags & TH_ACK) printf("ACK ");
                if (header->th_flags & TH_URG) printf("URG ");
                printf(", seq=%u, ack=%u\n",header->th_seq,header->th_ack);

                //tell the other side about the next expected bit

                tcp_seq next_expected_seq = (data_bytes > 0) ? (header->th_seq + data_bytes):(header->th_seq + 1);


                if (data_bytes > 0 || (header->th_flags & TH_FIN))
                {
                    //printf("receive normal data packet or empty fin or data packet with fin flag\n");
                    if (data_bytes > 0) { stcp_app_send(sd, data, data_bytes);} // send to app regardless

                    // send ack
                    STCPHeader ack_packet = {0};
                    ack_packet.th_flags = TH_ACK;
                    ack_packet.th_seq = ctx->next_seq_to_send;
                    ack_packet.th_ack = next_expected_seq;
                    ack_packet.th_off = 5;

                    if (stcp_network_send(sd, &ack_packet, sizeof(ack_packet), NULL) == -1){
                        perror("Failed to send ACK");
                        return;
                    }
                    // send ack, no need to update ctx->next_seq_to_send
                    printf("Sent ack, seq=%u, ack=%u\n",ack_packet.th_seq,ack_packet.th_ack);
                }//receive data packet or fin or data packet with fin flag

                if ((header->th_flags & TH_ACK))
                {//basically we already send fin and is now waiting for the final ack, and now we get it, so we close
                    if(header->th_ack == ctx->next_seq_to_send){
                        //printf("ack relates to the newest sent item(if fin, this should be the ack for fin)\n");
                        if(ctx->connection_state == CSTATE_LAST_ACK_PASSIVE){
                            //printf("terminating as ack received under waiting for last ack passive state\n");
                            ctx->done = 1;
                        }else if(ctx->connection_state == CSTATE_WAITING_FOR_FINACK_ACTIVE){//for the active one, it sends fin, get ack, now it should be expecting a fin from the other side
                            //printf("fin ack received under state waiting_for_fin_ack_active, switch to state wait for fin\n");
                            ctx->connection_state = CSTATE_WAITING_FOR_FIN_ACTIVE;
                        } //receive fin-ack
                    }
                } // received ack

                if (header->th_flags & TH_FIN){//if we are suppose to terminate(passive)

                    if(ctx->connection_state == CSTATE_ESTABLISHED) {
                        //sent ack already
                        ctx->connection_state = CSTATE_CLOSE_WAIT_PASSIVE;
                    }
                    if(ctx->connection_state == CSTATE_WAITING_FOR_FIN_ACTIVE){
                        //printf("fin received under waiting for fin_active, terminating\n");
                        //in this case we should just send an ack and then terminate

                        //sent ack already
                        ctx->connection_state = CSTATE_TIME_WAIT_ACTIVE; // wiat 2MSL
                    }

                    //the only other possible case of getting a fin is being the passive side and receive a fin,
                    //in this case we send an ack along with our own fin, then wait for the other side
                    if (ctx->connection_state == CSTATE_CLOSE_WAIT_PASSIVE){

                        //send fin
                        //printf("fin received under case established, sending fin and change state to wait_for_finack_passive\n");
                        STCPHeader fin_packet = {0};
                        fin_packet.th_flags = TH_FIN;
                        fin_packet.th_seq = ctx->next_seq_to_send;
                        fin_packet.th_off = 5;

                        if (stcp_network_send(sd, &fin_packet, sizeof(STCPHeader), NULL) == -1){
                            perror("Failed to send FIN");
                            return;
                        }
                        ctx->next_seq_to_send++;
                        ctx->connection_state = CSTATE_LAST_ACK_PASSIVE;//now we are just waiting for the ack from the other side
                        ctx->time_out = time(NULL);
                        printf("Sent fin, seq=%u\n",fin_packet.th_seq);
                    }
                }
            }else{
                printf("ELSE!!!\n");
            }
        }//event & NETWORK_DATA

        if (event & APP_CLOSE_REQUESTED) {//do the handshake for termination(only for active since only it will get notified by the application)
            //printf("APP_CLOSE_REQUESTED: sending fin as application requirement\n");
            STCPHeader fin_packet = {0};
            fin_packet.th_flags = TH_FIN;
            fin_packet.th_seq = ctx->next_seq_to_send;
            fin_packet.th_off = 5;

            if (stcp_network_send(sd, &fin_packet, sizeof(fin_packet), NULL) == -1){
                perror("Failed to send FIN");
                return;
            }
            ctx->next_seq_to_send++;
            ctx->connection_state = CSTATE_WAITING_FOR_FINACK_ACTIVE; //now we sent the fin, wait for the other side's response
            printf("Sent fin, seq=%u\n",fin_packet.th_seq);
        }

        if (event & ANY_EVENT) {
            if ((ctx->connection_state == CSTATE_LAST_ACK_PASSIVE||
                ctx->connection_state == CSTATE_TIME_WAIT_ACTIVE) &&
                    time(NULL) - ctx->time_out >= 2*MSL) {
                printf("Close timeout reached. Closing connection.\n");
                ctx->done = 1;
            }
        }
        /* etc. */
    }
    // close connect
    stcp_fin_received(sd);
    printf("disconnect\n");
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



