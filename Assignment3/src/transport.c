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
#include <unistd.h>
#include <arpa/inet.h>

#define FIN_TIMEOUT 2 
#define MAX_WIN 1200

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
        syn_packet.th_off = htons(5);
        syn_packet.th_win = htons(MAX_WIN);
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
                printf("syn_ack_packet.th_ack: %u\n", syn_ack_packet.th_ack);
                printf("ctx->next_seq_to_send: %u\n", ctx->next_seq_to_send);
                ctx->last_ack_received = ntohl(syn_ack_packet.th_ack);
                break;
            }
        }

        // send ack
        STCPHeader ack_packet = {0};
        ack_packet.th_flags = TH_ACK;//just use normal ack this time
        ack_packet.th_seq = htonl(ctx->next_seq_to_send);//the sequence number(+1 since ack and syn here takes 1 even if no payload exists)
        ack_packet.th_ack = htonl(ntohl(syn_ack_packet.th_seq) + 1);//next expected number
        ack_packet.th_off = htons(5);
        ack_packet.th_win = htons(MAX_WIN);
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
                ctx->last_ack_received = ntohl(syn_packet.th_ack);
                break;
            }
        }

        // send syn ack
        STCPHeader syn_ack_packet = {0};
        syn_ack_packet.th_flags = TH_SYN | TH_ACK;
        syn_ack_packet.th_seq = htonl(ctx->next_seq_to_send);
        syn_ack_packet.th_ack = htonl(ntohl(syn_packet.th_seq) + 1);
        syn_ack_packet.th_off = htons(5);
        syn_ack_packet.th_win = htons(MAX_WIN);
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
                ctx->last_ack_received = ntohl(ack_packet.th_ack);
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
            //printf("sent\n");
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
            char *buffer = (char *)malloc(STCP_MSS);
            ssize_t bytes_read;


            if ((bytes_read = stcp_app_recv(sd, buffer, STCP_MSS)) > 0){//cut large chunk of data into smaller packets
               // printf("Bytes read from app: %zd\n", bytes_read);
                enqueue(&ctx->data_queue, buffer, bytes_read);
               // printf("Sending packet: SEQ=%u, Payload Size=%zd\n", data_packet.th_seq, bytes_read);
            }

            //printf("sent-end\n");
        }

        if (event & NETWORK_DATA) {
           // printf("network receive 1\n");
            /* received data from STCP peer */
            char buffer[1024];
            ssize_t bytes_received = stcp_network_recv(sd, buffer, sizeof(buffer));
            
            //printf("network receive 2\n");
            if (bytes_received > 0) {//similarly, if received from peer, send to app
                STCPHeader *header = (STCPHeader *)buffer;
                char *data = buffer + 20;
                ssize_t data_bytes = bytes_received - 20;

                //printf("Flags set: ");
                //if (header->th_flags & TH_FIN) printf("FIN ");
                //if (header->th_flags & TH_SYN) printf("SYN ");
                //if (header->th_flags & TH_RST) printf("RST ");
                //if (header->th_flags & TH_PUSH) printf("PUSH ");
                //if (header->th_flags & TH_ACK) printf("ACK ");
                //if (header->th_flags & TH_URG) printf("URG ");
                //printf("\n");

                tcp_seq local_seq_num = ntohl(header->th_seq);
                //tell the other side about the next expected bit
                tcp_seq next_expected_seq = (data_bytes > 0) ? (local_seq_num + data_bytes):(local_seq_num + 1);
                //printf("network receive 3\n");
                //receiver died here

                if (data_bytes > 0 || (header->th_flags & TH_FIN)){//send to app regardless
                    if(data_bytes > 0){
                        stcp_app_send(sd, data, data_bytes);
                        printf("Receiving a normal payload of size %zd bytes\n", data_bytes);
                    }
                    
                    sleep(2);//for testing sake, wait a bit
                        printf("sending ack\n");
                                            //otherwise if the header is not ack, we give it an ack back
                                            
                    STCPHeader ack_packet = {0};
                    ack_packet.th_flags = TH_ACK;
                    ack_packet.th_seq = htonl(ctx->next_seq_to_send);
                    ack_packet.th_ack = htonl(next_expected_seq);
                    ack_packet.th_off = htons(5);
                    ack_packet.th_win = htons(MAX_WIN);

                    if (stcp_network_send(sd, &ack_packet, sizeof(ack_packet), NULL) == -1){
                        perror("Failed to send ACK");
                        return;
                    }
                }

                    //printf("received\n");
                    if ((header->th_flags & TH_ACK)){//basically we already send fin and is now waiting for the final ack, and now we get it, so we close
                        printf("ack received\n");
                        tcp_seq local_ack_num = ntohl(header->th_ack);
                        ctx->last_ack_received = local_ack_num;
                        if(local_ack_num == ctx->next_seq_to_send){
                            printf("ack relates to the newest sent item(if fin, this should be the ack for fin)\n");
                            if(ctx->connection_state == CSTATE_WAITING_FOR_FINACK_PASSIVE){
                                printf("terminating as ack received under waiting for finack passive state\n");
                            ctx->done = true;
                            stcp_fin_received(sd);
                            break;
                        }else if(ctx->connection_state == CSTATE_WAITING_FOR_FINACK_ACTIVE){//for the active one, it sends fin, get ack, now it should be expecting a fin from the other side
                            
                            printf("fin ack received under state waiting_for_fin_ack_active, switch to state wait for fin\n");
                            ctx->connection_state = CSTATE_WAITING_FOR_FIN_ACTIVE;
                        }
                        }
                        
                    }

                    if (header->th_flags & TH_FIN){//if we are suppose to terminate(passive)
                   // printf("fin-received\n");
                   printf("received fin\n");

                    if(ctx->connection_state == CSTATE_WAITING_FOR_FIN_ACTIVE){
                        //printf("got fin from other side\n");
                        printf("fin received under waiting for fin_active, terminating\n");
                        ctx->done = true;
                        stcp_fin_received(sd);
                        break;
                        //in this case we should just send an ack and then terminate, we already sent ack in the past
                    }

                    //the only other possible case of getting a fin is being the passive side and receive a fin, in this case we send an ack along with our own fin, then wait for the other side
                    //also send our own fin
                    if (ctx->connection_state == CSTATE_ESTABLISHED){
                        ctx->fin_sent_time = time(NULL);
                        printf("fin received under case established, sending fin and change state to wait_for_finack_passive\n");
                        STCPHeader fin_packet = {0};                
                        fin_packet.th_flags = TH_FIN;
                        fin_packet.th_seq = htonl(ctx->next_seq_to_send);
                        fin_packet.th_off = htons(5);
                        fin_packet.th_win = htons(MAX_WIN);

                        if (stcp_network_send(sd, &fin_packet, sizeof(fin_packet), NULL) == -1){
                            perror("Failed to send FIN");
                            return;
                        }
                        ctx->next_seq_to_send++;
                        ctx->connection_state = CSTATE_WAITING_FOR_FINACK_PASSIVE;//now we are just waiting for the ack from the other side
                    }
                    
                   // printf("fin-received-end\n");
                }


                    //printf("Receiving packet: SEQ=%u, ACK=%u\n", header->th_seq, header->th_ack);

                    //printf("received-end\n");
                

                
            }else{
                //printf("ELSE!!!\n");
            }
        }

        if (event & APP_CLOSE_REQUESTED) {//do the handshake for termination(only for active since only it will get notified by the application)
            printf("sending fin as application requirement\n");
            STCPHeader fin_packet = {0};
            fin_packet.th_flags = TH_FIN;
            fin_packet.th_seq = htonl(ctx->next_seq_to_send);
            fin_packet.th_off = htons(5);
            fin_packet.th_win = htons(MAX_WIN);

            if (stcp_network_send(sd, &fin_packet, sizeof(fin_packet), NULL) == -1){
                perror("Failed to send FIN");
                return;
            }
            
            ctx->next_seq_to_send++;

            ctx->connection_state = CSTATE_WAITING_FOR_FINACK_ACTIVE; //now we sent the fin, wait for the other side's response
            ctx->fin_sent_time = time(NULL);
        }


        if ((ctx->connection_state == CSTATE_WAITING_FOR_FINACK_PASSIVE || ctx->connection_state == CSTATE_WAITING_FOR_FINACK_ACTIVE) &&
            time(NULL) - ctx->fin_sent_time >= FIN_TIMEOUT) {
            printf("FIN-ACK timeout reached. Closing connection.\n");
            ctx->done = true;
            stcp_fin_received(sd);
        }

        while (ctx->connection_state == CSTATE_ESTABLISHED && ctx->data_queue.head && (ctx->last_ack_received + MAX_WIN > ctx->next_seq_to_send + ctx->data_queue.head->size)) {
            queue_node_t *current = ctx->data_queue.head;
            STCPHeader data_packet = {0};
            data_packet.th_seq = htonl(ctx->next_seq_to_send);
            data_packet.th_flags = NETWORK_DATA;
            data_packet.th_off = htons(5);
            data_packet.th_win = htons(MAX_WIN);
            //put the header and packet together
            char send_buffer[20 + current->size];
            memcpy(send_buffer, &data_packet,20);
            memcpy(send_buffer + 20, current->data, current->size);

            if (stcp_network_send(sd, send_buffer, sizeof(STCPHeader) + current->size, NULL) == -1) {
                perror("Failed to send data");
                free(send_buffer);
                return;
            }
            printf("Sent data of size: %zd bytes\n", current->size);

            ctx->next_seq_to_send += current->size;
            dequeue(&ctx->data_queue);  // Remove the sent data from the queue
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



