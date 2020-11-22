/* Copyright (C) 2015-2020 Open Information Security Foundation
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
 * TODO: Update \author in this file and app-layer-iec104.h.
 * TODO: Implement your app-layer logic with unit tests.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * IEC104 application layer detector and parser for learning and
 * iec104 pruposes.
 *
 * This iec104 implements a simple application layer for something
 * like the echo protocol running on port 7.
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"
#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"
#include "app-layer-iec104.h"

#include "util-unittest.h"
#include "util-validate.h"

/* The default port to probe for echo traffic if not provided in the
 * configuration file. */
#define IEC104_DEFAULT_PORT "2404"

/* The minimum size for a message. For some protocols this might
 * be the size of a header. */
#define IEC104_MIN_FRAME_LEN 1

/* Enum of app-layer events for the protocol. Normally you might
 * have events for errors in parsing data, like unexpected data being
 * received. For iec104 we'll make something up, and log an app-layer
 * level alert if an empty message is received.
 *
 * Example rule:
 *
 * alert iec104 any any -> any any (msg:"SURICATA IEC104 empty message"; \
 *    app-layer-event:iec104.empty_message; sid:X; rev:Y;)
 */
enum {
    IEC104_DECODER_EVENT_EMPTY_MESSAGE,
};

SCEnumCharMap iec104_decoder_event_table[] = {
    {"EMPTY_MESSAGE", IEC104_DECODER_EVENT_EMPTY_MESSAGE},

    // event table must be NULL-terminated
    { NULL, -1 },
};

static IEC104Transaction *IEC104TxAlloc(IEC104State *state)
{
    IEC104Transaction *tx = SCCalloc(1, sizeof(IEC104Transaction));
    if (unlikely(tx == NULL)) {
        return NULL;
    }

    /* Increment the transaction ID on the state each time one is
     * allocated. */
    tx->tx_id = state->transaction_max++;

    TAILQ_INSERT_TAIL(&state->tx_list, tx, next);

    return tx;
}

static void IEC104TxFree(void *txv)
{
    IEC104Transaction *tx = txv;

    if (tx->request_buffer != NULL) {
        SCFree(tx->request_buffer);
    }

    if (tx->response_buffer != NULL) {
        SCFree(tx->response_buffer);
    }

    AppLayerDecoderEventsFreeEvents(&tx->decoder_events);

    SCFree(tx);
}

static void *IEC104StateAlloc(void *orig_state, AppProto proto_orig)
{
    SCLogNotice("Allocating iec104 state.");
    IEC104State *state = SCCalloc(1, sizeof(IEC104State));
    if (unlikely(state == NULL)) {
        return NULL;
    }
    TAILQ_INIT(&state->tx_list);
    return state;
}

static void IEC104StateFree(void *state)
{
    IEC104State *iec104_state = state;
    IEC104Transaction *tx;
    SCLogNotice("Freeing iec104 state.");
    while ((tx = TAILQ_FIRST(&iec104_state->tx_list)) != NULL) {
        TAILQ_REMOVE(&iec104_state->tx_list, tx, next);
        IEC104TxFree(tx);
    }
    SCFree(iec104_state);
}

/**
 * \brief Callback from the application layer to have a transaction freed.
 *
 * \param state a void pointer to the IEC104State object.
 * \param tx_id the transaction ID to free.
 */
static void IEC104StateTxFree(void *statev, uint64_t tx_id)
{
    IEC104State *state = statev;
    IEC104Transaction *tx = NULL, *ttx;

    SCLogNotice("Freeing transaction %"PRIu64, tx_id);

    TAILQ_FOREACH_SAFE(tx, &state->tx_list, next, ttx) {

        /* Continue if this is not the transaction we are looking
         * for. */
        if (tx->tx_id != tx_id) {
            continue;
        }

        /* Remove and free the transaction. */
        TAILQ_REMOVE(&state->tx_list, tx, next);
        IEC104TxFree(tx);
        return;
    }

    SCLogNotice("Transaction %"PRIu64" not found.", tx_id);
}

static int IEC104StateGetEventInfo(const char *event_name, int *event_id,
    AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, iec104_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "iec104 enum map table.",  event_name);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static int IEC104StateGetEventInfoById(int event_id, const char **event_name,
                                         AppLayerEventType *event_type)
{
    *event_name = SCMapEnumValueToName(event_id, iec104_decoder_event_table);
    if (*event_name == NULL) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%d\" not present in "
                   "iec104 enum map table.",  event_id);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static AppLayerDecoderEvents *IEC104GetEvents(void *tx)
{
    return ((IEC104Transaction *)tx)->decoder_events;
}

/**
 * \brief Probe the input to server to see if it looks like iec104.
 *
 * \retval ALPROTO_IEC104 if it looks like iec104,
 *     ALPROTO_FAILED, if it is clearly not ALPROTO_IEC104,
 *     otherwise ALPROTO_UNKNOWN.
 */
static AppProto IEC104ProbingParserTs(Flow *f, uint8_t direction,
        const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{
    /* Very simple test - if there is input, this is iec104. */
    if (input_len >= IEC104_MIN_FRAME_LEN) {
        SCLogNotice("Detected as ALPROTO_IEC104.");
        return ALPROTO_IEC104;
    }

    SCLogNotice("Protocol not detected as ALPROTO_IEC104.");
    return ALPROTO_UNKNOWN;
}

/**
 * \brief Probe the input to client to see if it looks like iec104.
 *     IEC104ProbingParserTs can be used instead if the protocol
 *     is symmetric.
 *
 * \retval ALPROTO_IEC104 if it looks like iec104,
 *     ALPROTO_FAILED, if it is clearly not ALPROTO_IEC104,
 *     otherwise ALPROTO_UNKNOWN.
 */
static AppProto IEC104ProbingParserTc(Flow *f, uint8_t direction,
        const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{
    /* Very simple test - if there is input, this is iec104. */
    if (input_len >= IEC104_MIN_FRAME_LEN) {
        SCLogNotice("Detected as ALPROTO_IEC104.");
        return ALPROTO_IEC104;
    }

    SCLogNotice("Protocol not detected as ALPROTO_IEC104.");
    return ALPROTO_UNKNOWN;
}

static AppLayerResult IEC104ParseRequest(Flow *f, void *statev,
    AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len,
    void *local_data, const uint8_t flags)
{
    IEC104State *state = statev;

    SCLogNotice("Parsing iec104 request: len=%"PRIu32, input_len);

    if (input == NULL) {
        if (AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS)) {
            /* This is a signal that the stream is done. Do any
             * cleanup if needed. Usually nothing is required here. */
            SCReturnStruct(APP_LAYER_OK);
        } else if (flags & STREAM_GAP) {
            /* This is a signal that there has been a gap in the
             * stream. This only needs to be handled if gaps were
             * enabled during protocol registration. The input_len
             * contains the size of the gap. */
            SCReturnStruct(APP_LAYER_OK);
        }
        /* This should not happen. If input is NULL, one of the above should be
         * true. */
        DEBUG_VALIDATE_BUG_ON(true);
        SCReturnStruct(APP_LAYER_ERROR);
    }

    /* Normally you would parse out data here and store it in the
     * transaction object, but as this is echo, we'll just record the
     * request data. */

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
    IEC104Transaction *tx = IEC104TxAlloc(state);
    if (unlikely(tx == NULL)) {
        SCLogNotice("Failed to allocate new IEC104 tx.");
        goto end;
    }
    SCLogNotice("Allocated IEC104 tx %"PRIu64".", tx->tx_id);

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
            IEC104_DECODER_EVENT_EMPTY_MESSAGE);
    }

end:
    SCReturnStruct(APP_LAYER_OK);
}

static AppLayerResult IEC104ParseResponse(Flow *f, void *statev, AppLayerParserState *pstate,
    const uint8_t *input, uint32_t input_len, void *local_data,
    const uint8_t flags)
{
    IEC104State *state = statev;
    IEC104Transaction *tx = NULL, *ttx;

    SCLogNotice("Parsing IEC104 response.");

    /* Likely connection closed, we can just return here. */
    if ((input == NULL || input_len == 0) &&
        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC)) {
        SCReturnStruct(APP_LAYER_OK);
    }

    /* Probably don't want to create a transaction in this case
     * either. */
    if (input == NULL || input_len == 0) {
        SCReturnStruct(APP_LAYER_OK);
    }

    /* Look up the existing transaction for this response. In the case
     * of echo, it will be the most recent transaction on the
     * IEC104State object. */

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
     * IEC104GetStateProgress(). */
    tx->response_done = 1;

end:
    SCReturnStruct(APP_LAYER_OK);
}

static uint64_t IEC104GetTxCnt(void *statev)
{
    const IEC104State *state = statev;
    SCLogNotice("Current tx count is %"PRIu64".", state->transaction_max);
    return state->transaction_max;
}

static void *IEC104GetTx(void *statev, uint64_t tx_id)
{
    IEC104State *state = statev;
    IEC104Transaction *tx;

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

/**
 * \brief Called by the application layer.
 *
 * In most cases 1 can be returned here.
 */
static int IEC104GetAlstateProgressCompletionStatus(uint8_t direction) {
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
static int IEC104GetStateProgress(void *txv, uint8_t direction)
{
    IEC104Transaction *tx = txv;

    SCLogNotice("Transaction progress requested for tx ID %"PRIu64
        ", direction=0x%02x", tx->tx_id, direction);

    if (direction & STREAM_TOCLIENT && tx->response_done) {
        return 1;
    }
    else if (direction & STREAM_TOSERVER) {
        /* For the iec104, just the existence of the transaction means the
         * request is done. */
        return 1;
    }

    return 0;
}

/**
 * \brief retrieve the tx data used for logging, config, detection
 */
static AppLayerTxData *IEC104GetTxData(void *vtx)
{
    IEC104Transaction *tx = vtx;
    return &tx->tx_data;
}

/**
 * \brief retrieve the detection engine per tx state
 */
static DetectEngineState *IEC104GetTxDetectState(void *vtx)
{
    IEC104Transaction *tx = vtx;
    return tx->de_state;
}

/**
 * \brief get the detection engine per tx state
 */
static int IEC104SetTxDetectState(void *vtx,
    DetectEngineState *s)
{
    IEC104Transaction *tx = vtx;
    tx->de_state = s;
    return 0;
}

void RegisterIEC104Parsers(void)
{
    const char *proto_name = "iec104";

    /* Check if IEC104 TCP detection is enabled. If it does not exist in
     * the configuration file then it will be enabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {

        SCLogNotice("IEC104 TCP protocol detection enabled.");

        AppLayerProtoDetectRegisterProtocol(ALPROTO_IEC104, proto_name);

        if (RunmodeIsUnittests()) {

            SCLogNotice("Unittest mode, registeringd default configuration.");
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, IEC104_DEFAULT_PORT,
                ALPROTO_IEC104, 0, IEC104_MIN_FRAME_LEN, STREAM_TOSERVER,
                IEC104ProbingParserTs, IEC104ProbingParserTc);

        }
        else {

            if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                    proto_name, ALPROTO_IEC104, 0, IEC104_MIN_FRAME_LEN,
                    IEC104ProbingParserTs, IEC104ProbingParserTc)) {
                SCLogNotice("No iec104 app-layer configuration, enabling echo"
                    " detection TCP detection on port %s.",
                    IEC104_DEFAULT_PORT);
                AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                    IEC104_DEFAULT_PORT, ALPROTO_IEC104, 0,
                    IEC104_MIN_FRAME_LEN, STREAM_TOSERVER,
                    IEC104ProbingParserTs, IEC104ProbingParserTc);
            }

        }

    }

    else {
        SCLogNotice("Protocol detecter and parser disabled for IEC104.");
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {

        SCLogNotice("Registering IEC104 protocol parser.");

        /* Register functions for state allocation and freeing. A
         * state is allocated for every new IEC104 flow. */
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_IEC104,
            IEC104StateAlloc, IEC104StateFree);

        /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_IEC104,
            STREAM_TOSERVER, IEC104ParseRequest);

        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_IEC104,
            STREAM_TOCLIENT, IEC104ParseResponse);

        /* Register a function to be called by the application layer
         * when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_IEC104,
            IEC104StateTxFree);

        /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_IEC104,
            IEC104GetTxCnt);

        /* Transaction handling. */
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_IEC104,
            IEC104GetAlstateProgressCompletionStatus);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP,
            ALPROTO_IEC104, IEC104GetStateProgress);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_IEC104,
            IEC104GetTx);
        AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_IEC104,
            IEC104GetTxData);

        /* What is this being registered for? */
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_IEC104,
            IEC104GetTxDetectState, IEC104SetTxDetectState);

        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_IEC104,
            IEC104StateGetEventInfo);
        AppLayerParserRegisterGetEventInfoById(IPPROTO_TCP, ALPROTO_IEC104,
            IEC104StateGetEventInfoById);
        AppLayerParserRegisterGetEventsFunc(IPPROTO_TCP, ALPROTO_IEC104,
            IEC104GetEvents);

        /* Leave this is if you parser can handle gaps, otherwise
         * remove. */
        AppLayerParserRegisterOptionFlags(IPPROTO_TCP, ALPROTO_IEC104,
            APP_LAYER_PARSER_OPT_ACCEPT_GAPS);
    }
    else {
        SCLogNotice("IEC104 protocol parsing disabled.");
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_IEC104,
        IEC104ParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void IEC104ParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}
