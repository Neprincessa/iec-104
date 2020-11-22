/* Copyright (C) 2015 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/*
 * TODO: Update \author in this file and app-layer-s7.h.
 * TODO: Implement your app-layer logic with unit tests.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * S7 application layer detector and parser for learning and
 * s7 pruposes.
 *
 * This s7 implements a simple application layer for something
 * like the echo protocol running on port 7.
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"
#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"
#include "app-layer-s7.h"

#include "util-unittest.h"


/* The default port to probe for echo traffic if not provided in the
 * configuration file. */
#define S7_DEFAULT_PORT "102"

/* The minimum size for a message. For some protocols this might
 * be the size of a header. */
#define S7_MIN_FRAME_LEN 8

/* Enum of app-layer events for the protocol. Normally you might
 * have events for errors in parsing data, like unexpected data being
 * received. For s7 we'll make something up, and log an app-layer
 * level alert if an empty message is received.
 *
 * Example rule:
 *
 * alert s7 any any -> any any (msg:"SURICATA S7 empty message"; \
 *    app-layer-event:s7.empty_message; sid:X; rev:Y;)
 */
enum {
    S7_DECODER_EVENT_EMPTY_MESSAGE,
    S7_DECODER_EVENT_JOB_MESSAGE,
};

SCEnumCharMap s7_decoder_event_table[] = {
    {"EMPTY_MESSAGE", S7_DECODER_EVENT_EMPTY_MESSAGE},
    {"JOB_MESSAGE", S7_DECODER_EVENT_JOB_MESSAGE},

    // event table must be NULL-terminated
    { NULL, -1 },
};

static S7Transaction *S7TxAlloc(S7State *state)
{
    S7Transaction *tx = SCCalloc(1, sizeof(S7Transaction));
    if (unlikely(tx == NULL)) {
        return NULL;
    }

    /* Increment the transaction ID on the state each time one is
     * allocated. */
    tx->tx_id = state->transaction_max++;

    TAILQ_INSERT_TAIL(&state->tx_list, tx, next);

    return tx;
}

static void S7TxFree(void *txv)
{
    S7Transaction *tx = txv;

    if (tx->request_buffer != NULL) {
        SCFree(tx->request_buffer);
    }

    if (tx->response_buffer != NULL) {
        SCFree(tx->response_buffer);
    }

    AppLayerDecoderEventsFreeEvents(&tx->decoder_events);

    SCFree(tx);
}

static void *S7StateAlloc(void)
{
    SCLogNotice("Allocating s7 state.");
    S7State *state = SCCalloc(1, sizeof(S7State));
    if (unlikely(state == NULL)) {
        return NULL;
    }
    TAILQ_INIT(&state->tx_list);
    return state;
}

static void S7StateFree(void *state)
{
    S7State *s7_state = state;
    S7Transaction *tx;
    SCLogNotice("Freeing s7 state.");
    while ((tx = TAILQ_FIRST(&s7_state->tx_list)) != NULL) {
        TAILQ_REMOVE(&s7_state->tx_list, tx, next);
        S7TxFree(tx);
    }
    SCFree(s7_state);
}

/**
 * \brief Callback from the application layer to have a transaction freed.
 *
 * \param state a void pointer to the S7State object.
 * \param tx_id the transaction ID to free.
 */
static void S7StateTxFree(void *statev, uint64_t tx_id)
{
    S7State *state = statev;
    S7Transaction *tx = NULL, *ttx;

    SCLogNotice("Freeing transaction %"PRIu64, tx_id);

    TAILQ_FOREACH_SAFE(tx, &state->tx_list, next, ttx) {

        /* Continue if this is not the transaction we are looking
         * for. */
        if (tx->tx_id != tx_id) {
            continue;
        }

        /* Remove and free the transaction. */
        TAILQ_REMOVE(&state->tx_list, tx, next);
        S7TxFree(tx);
        return;
    }

    SCLogNotice("Transaction %"PRIu64" not found.", tx_id);
}

static int S7StateGetEventInfo(const char *event_name, int *event_id,
    AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, s7_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "s7 enum map table.",  event_name);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static int S7StateGetEventInfoById(int event_id, const char **event_name,
                                         AppLayerEventType *event_type)
{
    *event_name = SCMapEnumValueToName(event_id, s7_decoder_event_table);
    if (*event_name == NULL) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%d\" not present in "
                   "s7 enum map table.",  event_id);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static AppLayerDecoderEvents *S7GetEvents(void *tx)
{
    return ((S7Transaction *)tx)->decoder_events;
}

/**
 * \brief Probe the input to server to see if it looks like s7.
 *
 * \retval ALPROTO_S7 if it looks like s7,
 *     ALPROTO_FAILED, if it is clearly not ALPROTO_S7,
 *     otherwise ALPROTO_UNKNOWN.
 */
static AppProto S7ProbingParserTs(Flow *f, uint8_t direction,
        const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{
    /* Very simple test - if there is input, this is s7. */
    if (input_len >= S7_MIN_FRAME_LEN){

	for (int i=0; i<input_len; i++){
		printf("%02X", *(input+i));
    	}
	printf("\n");
	SCLogNotice("Hi");
	
	if (*(input+0) == 0x03)
	    if (*(input+1) == 0x00)
		if (*(input+2) == 0x00)
		    if (*(input+3) == 0x16){
			SCLogNotice("Detected as ALPROTO_S7. pos_1");
            		return ALPROTO_S7;
		    }

        if (*(input+7) == 0x32){
            SCLogNotice("Detected as ALPROTO_S7. pos_1");
            return ALPROTO_S7;
 	    
	}
    }

    SCLogNotice("Protocol not detected as ALPROTO_S7. ");
    return ALPROTO_UNKNOWN;
}

/**
 * \brief Probe the input to client to see if it looks like s7.
 *     S7ProbingParserTs can be used instead if the protocol
 *     is symmetric.
 *
 * \retval ALPROTO_S7 if it looks like s7,
 *     ALPROTO_FAILED, if it is clearly not ALPROTO_S7,
 *     otherwise ALPROTO_UNKNOWN.
 */
static AppProto S7ProbingParserTc(Flow *f, uint8_t direction,
        const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{
    /* Very simple test - if there is input, this is s7. */
    if (input_len >= S7_MIN_FRAME_LEN){

	for (int i=0; i<input_len; i++){
		printf("%02X", *(input+i));
    	}
	printf("\n");
	SCLogNotice("Hi");

	if (*(input+0) == 0x03)
	    if (*(input+1) == 0x00)
		if (*(input+2) == 0x00)
		    if (*(input+3) == 0x16){
			SCLogNotice("Detected as ALPROTO_S7. pos_1");
            		return ALPROTO_S7;
		    }

        if (*(input+6) == 0x32){
            SCLogNotice("Detected as ALPROTO_S7. pos_2");
            printf("%02X", *(input+7));
            return ALPROTO_S7;
 	    
	}
    }
    

    SCLogNotice("Protocol not detected as ALPROTO_S7. <-");
    return ALPROTO_UNKNOWN;
}

static int S7ParamDataExtract(const uint8_t *input, const uint16_t paramOffset, const uint16_t paramLen, const uint16_t dataLen)
{
	if(!input||!paramOffset||!paramLen)
		SCLogNotice("NOINITERROR");
	
	uint8_t* param = SCMalloc(paramLen);
	for (uint16_t i = 0; i<paramLen; i++){
		*(param+i) = *(input+paramOffset+i);	//19
		printf("%02X", *(param+i));
	}
	printf("\n");	
	uint8_t* data = SCMalloc(dataLen);
	for (uint16_t i = 0; i<dataLen; i++){
		*(data+i) = *(input+paramOffset+paramLen+i);
		printf("%c", *(data+i));
	}
	printf("\n");
	SCFree(param);
	SCFree(data);
}

static int S7ParseRequest(Flow *f, void *statev,
    AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len,
    void *local_data, const uint8_t flags)
{
    S7State *state = statev;


    SCLogNotice("-------------------------------\n");
    for (uint32_t i=0; i<input_len; i++){
	printf("%02X", *(input+i));
    }
    printf("\n");
    if (input_len >= 7){
    	printf("%02X", *(input+7));
	printf("\n");
        if (*(input+7) == 0x32)
	    SCLogNotice("YES\n");
	else
	    SCLogNotice("NO\n");
    }
    printf("\n");
    
    
    SCLogNotice("-------------------------------\n");
    SCLogNotice("Parsing s7 request: len=%"PRIu32, input_len);

    /* Likely connection closed, we can just return here. */
    if ((input == NULL || input_len == 0) &&
        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        return 0;
    }

    /* Probably don't want to create a transaction in this case
     * either. */
    if (input == NULL || input_len == 0) {
        return 0;
    }

    /* Normally you would parse out data here and store it in the
     * transaction object, but as this is echo, we'll just record the
     * request data. */
	uint8_t msgType = *(input+8);
	uint16_t paramLen = *(input+14) + *(input+13)*256; 
 	uint16_t dataLen = *(input+16) + *(input+15)*256;
	SCLogNotice("Message Code=%"PRIu8, msgType);
	SCLogNotice("Paramlen=%"PRIu16, paramLen);
	SCLogNotice("Datalen=%"PRIu16, dataLen);

	uint16_t paramOffsetDF = 17;	

	switch(msgType){
		case 1:
		if(*(input+paramOffsetDF) == 240)
			SCLogNotice("Message Type is Job setup:");
		if(*(input+paramOffsetDF) == 4)
			SCLogNotice("Message Type is Job read:");
		if(*(input+paramOffsetDF) == 5)
			SCLogNotice("Message Type is Job write:");
		S7ParamDataExtract(input, paramOffsetDF, paramLen, dataLen);
		break;
		case 2:
		SCLogNotice("Message Type is Ack:");
		S7ParamDataExtract(input, paramOffsetDF, paramLen, dataLen);
		break;
		case 3:
		SCLogNotice("Ack-Data:");
		S7ParamDataExtract(input, paramOffsetDF+2, paramLen, dataLen);
		break;
		case 7:
		SCLogNotice("Message Type is UserData:");
		S7ParamDataExtract(input, paramOffsetDF, paramLen, dataLen);
		break;
	}

    /* Also, if this protocol may have a "protocol data unit" span
     * multiple chunks of data, which is always a possibility with
     * TCP, you may need to do some buffering here.
     *
     * For the sake of simplicity, buffering is left out here, but
     * even for an echo protocol we may want to buffer until a new
     * line is seen, assuming its text based.
     */

    /* Allocate a transaction.
     *
     * But note that if a "protocol data unit" is not received in one
     * chunk of data, and the buffering is done on the transaction, we
     * may need to look for the transaction that this newly recieved
     * data belongs to.
     */
    S7Transaction *tx = S7TxAlloc(state);
    if (unlikely(tx == NULL)) {
        SCLogNotice("Failed to allocate new S7 tx.");
        goto end;
    }
    SCLogNotice("Allocated S7 tx %"PRIu64".", tx->tx_id);

    /* Make a copy of the request. */
    tx->request_buffer = SCCalloc(1, input_len);
    if (unlikely(tx->request_buffer == NULL)) {
        goto end;
    }
    memcpy(tx->request_buffer, input, input_len);
    tx->request_buffer_len = input_len;

    /* Here we check for an empty message and create an app-layer
     * event. */
    if ((input_len == 1 && tx->request_buffer[0] == '\n') ||
        (input_len == 2 && tx->request_buffer[0] == '\r')) {
        SCLogNotice("Creating event for empty message.");
        AppLayerDecoderEventsSetEventRaw(&tx->decoder_events,
            S7_DECODER_EVENT_EMPTY_MESSAGE);
    }
	
    if (msgType == 1 && 
	((*(input+paramOffsetDF) == 4) || (*(input+paramOffsetDF) == 5) || (*(input+paramOffsetDF) == 240))) {
        SCLogNotice("Creating event for Job message.");
        AppLayerDecoderEventsSetEventRaw(&tx->decoder_events,
            S7_DECODER_EVENT_JOB_MESSAGE);
    }

end:
    return 0;
}

static int S7ParseResponse(Flow *f, void *statev, AppLayerParserState *pstate,
    const uint8_t *input, uint32_t input_len, void *local_data,
    const uint8_t flags)
{
    S7State *state = statev;
    S7Transaction *tx = NULL, *ttx;

    SCLogNotice("Parsing S7 response.");

    /* Likely connection closed, we can just return here. */
    if ((input == NULL || input_len == 0) &&
        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        return 0;
    }

    /* Probably don't want to create a transaction in this case
     * either. */
    if (input == NULL || input_len == 0) {
        return 0;
    }

    /* Look up the existing transaction for this response. In the case
     * of echo, it will be the most recent transaction on the
     * S7State object. */

    /* We should just grab the last transaction, but this is to
     * illustrate how you might traverse the transaction list to find
     * the transaction associated with this response. */
    TAILQ_FOREACH(ttx, &state->tx_list, next) {
        tx = ttx;
    }

    if (tx == NULL) {
        SCLogNotice("Failed to find transaction for response on state %p.",
            state);
        goto end;
    }

    SCLogNotice("Found transaction %"PRIu64" for response on state %p.",
        tx->tx_id, state);

    /* If the protocol requires multiple chunks of data to complete, you may
     * run into the case where you have existing response data.
     *
     * In this case, we just log that there is existing data and free it. But
     * you might want to realloc the buffer and append the data.
     */
    if (tx->response_buffer != NULL) {
        SCLogNotice("WARNING: Transaction already has response data, "
            "existing data will be overwritten.");
        SCFree(tx->response_buffer);
    }

    /* Make a copy of the response. */
    tx->response_buffer = SCCalloc(1, input_len);
    if (unlikely(tx->response_buffer == NULL)) {
        goto end;
    }
    memcpy(tx->response_buffer, input, input_len);
    tx->response_buffer_len = input_len;

    /* Set the response_done flag for transaction state checking in
     * S7GetStateProgress(). */
    tx->response_done = 1;

end:
    return 0;
}

static uint64_t S7GetTxCnt(void *statev)
{
    const S7State *state = statev;
    SCLogNotice("Current tx count is %"PRIu64".", state->transaction_max);
    return state->transaction_max;
}

static void *S7GetTx(void *statev, uint64_t tx_id)
{
    S7State *state = statev;
    S7Transaction *tx;

    SCLogNotice("Requested tx ID %"PRIu64".", tx_id);

    TAILQ_FOREACH(tx, &state->tx_list, next) {
        if (tx->tx_id == tx_id) {
            SCLogNotice("Transaction %"PRIu64" found, returning tx object %p.",
                tx_id, tx);
            return tx;
        }
    }

    SCLogNotice("Transaction ID %"PRIu64" not found.", tx_id);
    return NULL;
}

static void S7SetTxLogged(void *state, void *vtx, LoggerId logged)
{
    S7Transaction *tx = (S7Transaction *)vtx;
    tx->logged = logged;
}

static LoggerId S7GetTxLogged(void *state, void *vtx)
{
    const S7Transaction *tx = (S7Transaction *)vtx;
    return tx->logged;
}

/**
 * \brief Called by the application layer.
 *
 * In most cases 1 can be returned here.
 */
static int S7GetAlstateProgressCompletionStatus(uint8_t direction) {
    return 1;
}

/**
 * \brief Return the state of a transaction in a given direction.
 *
 * In the case of the echo protocol, the existence of a transaction
 * means that the request is done. However, some protocols that may
 * need multiple chunks of data to complete the request may need more
 * than just the existence of a transaction for the request to be
 * considered complete.
 *
 * For the response to be considered done, the response for a request
 * needs to be seen.  The response_done flag is set on response for
 * checking here.
 */
static int S7GetStateProgress(void *txv, uint8_t direction)
{
    S7Transaction *tx = txv;

    SCLogNotice("Transaction progress requested for tx ID %"PRIu64
        ", direction=0x%02x", tx->tx_id, direction);

    if (direction & STREAM_TOCLIENT && tx->response_done) {
        return 1;
    }
    else if (direction & STREAM_TOSERVER) {
        /* For the s7, just the existence of the transaction means the
         * request is done. */
        return 1;
    }

    return 0;
}

/**
 * \brief retrieve the detection engine per tx state
 */
static DetectEngineState *S7GetTxDetectState(void *vtx)
{
    S7Transaction *tx = vtx;
    return tx->de_state;
}

/**
 * \brief get the detection engine per tx state
 */
static int S7SetTxDetectState(void *vtx,
    DetectEngineState *s)
{
    S7Transaction *tx = vtx;
    tx->de_state = s;
    return 0;
}

void RegisterS7Parsers(void)
{
    const char *proto_name = "s7";

    /* Check if S7 TCP detection is enabled. If it does not exist in
     * the configuration file then it will be enabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {

        SCLogNotice("S7 TCP protocol detection enabled.");

        AppLayerProtoDetectRegisterProtocol(ALPROTO_S7, proto_name);

        if (RunmodeIsUnittests()) {

            SCLogNotice("Unittest mode, registeringd default configuration.");
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, S7_DEFAULT_PORT,
                ALPROTO_S7, 0, S7_MIN_FRAME_LEN, STREAM_TOSERVER,
                S7ProbingParserTs, S7ProbingParserTc);

        }
        else {

            if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                    proto_name, ALPROTO_S7, 0, S7_MIN_FRAME_LEN,
                    S7ProbingParserTs, S7ProbingParserTc)) {
                SCLogNotice("No s7 app-layer configuration, enabling echo"
                    " detection TCP detection on port %s.",
                    S7_DEFAULT_PORT);
                AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                    S7_DEFAULT_PORT, ALPROTO_S7, 0,
                    S7_MIN_FRAME_LEN, STREAM_TOSERVER,
                    S7ProbingParserTs, S7ProbingParserTc);
            }

        }

    }

    else {
        SCLogNotice("Protocol detecter and parser disabled for S7.");
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {

        SCLogNotice("Registering S7 protocol parser.");

        /* Register functions for state allocation and freeing. A
         * state is allocated for every new S7 flow. */
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_S7,
            S7StateAlloc, S7StateFree);

        /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_S7,
            STREAM_TOSERVER, S7ParseRequest);

        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_S7,
            STREAM_TOCLIENT, S7ParseResponse);

        /* Register a function to be called by the application layer
         * when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_S7,
            S7StateTxFree);

        AppLayerParserRegisterLoggerFuncs(IPPROTO_TCP, ALPROTO_S7,
            S7GetTxLogged, S7SetTxLogged);

        /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_S7,
            S7GetTxCnt);

        /* Transaction handling. */
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_S7,
            S7GetAlstateProgressCompletionStatus);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP,
            ALPROTO_S7, S7GetStateProgress);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_S7,
            S7GetTx);

        /* What is this being registered for? */
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_S7,
            S7GetTxDetectState, S7SetTxDetectState);

        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_S7,
            S7StateGetEventInfo);
        AppLayerParserRegisterGetEventInfoById(IPPROTO_TCP, ALPROTO_S7,
            S7StateGetEventInfoById);
        AppLayerParserRegisterGetEventsFunc(IPPROTO_TCP, ALPROTO_S7,
            S7GetEvents);
    }
    else {
        SCLogNotice("S7 protocol parsing disabled.");
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_S7,
        S7ParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void S7ParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}
