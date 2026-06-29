/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file rdk_log_suppressor.h
 * @brief Shared types and function declarations for the RDK log suppressor.
 *
 * Provides the interface between the config reader, detection engine,
 * summary formatter, and the integration point in rdk_debug_priv.c.
 *
 * RFC parameters:
 *   Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.RDKLogSuppressor.Enable
 *   Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.RDKLogSuppressor.MaxPatternLength
 */

#ifndef _RDK_LOG_SUPPRESSOR_H
#define _RDK_LOG_SUPPRESSOR_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include "rdk_debug.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -----------------------------------------------------------------------
 * Constants
 * --------------------------------------------------------------------- */

/** Maximum value allowed for MaxPatternLength RFC parameter (AC-5) */
#define RDK_SUPPRESSOR_MAX_PATTERN_LENGTH_LIMIT   20u

/** Default MaxPatternLength when RFC value is missing or out of range (AC-5) */
#define RDK_SUPPRESSOR_DEFAULT_MAX_PATTERN_LENGTH 10u

/** Maximum message buffer size — must match LOG4C_MSG_BUFFER_SIZE in rdk_debug_priv.c */
#define RDK_SUPPRESSOR_MSG_SIZE  980

/** Maximum module name length */
#define RDK_SUPPRESSOR_MODULE_SIZE 64


/* -----------------------------------------------------------------------
 * Configuration (AC-4, AC-5)
 * Populated once at rdk_suppressor_init(), read-only after that.
 * --------------------------------------------------------------------- */
typedef struct {
    bool         enabled;              /**< RFC Enable value (default: false)    */
    unsigned int max_pattern_length;   /**< RFC MaxPatternLength (1-20, default 10) */
    unsigned int history_buffer_size;  /**< Always 2 * max_pattern_length (AC-6) */
} rdk_suppressor_config_t;

/* -----------------------------------------------------------------------
 * Log entry stored in history / pattern buffers
 * --------------------------------------------------------------------- */
typedef struct {
    char         module_name[RDK_SUPPRESSOR_MODULE_SIZE];
    char         message[RDK_SUPPRESSOR_MSG_SIZE];
    rdk_LogLevel level;
    uint32_t     fingerprint;  /**< FNV-1a hash for fast mismatch rejection */
} rdk_log_entry_t;

/* -----------------------------------------------------------------------
 * Engine state
 * --------------------------------------------------------------------- */
typedef struct {
    rdk_log_entry_t *history;           /**< Heap-allocated circular buffer    */
    int              history_head;      /**< Next write position               */
    int              history_count;     /**< Entries currently in buffer       */

    rdk_log_entry_t *pattern;           /**< Heap-allocated pattern buffer     */
    int              pattern_length;    /**< 0 = no active pattern             */
    int              next_expected_idx; /**< Next position to match in pattern */
    unsigned int     repeat_count;      /**< Complete cycles suppressed        */
    time_t           first_timestamp;
    time_t           last_timestamp;

    /* Timing classification (burst/periodic/sporadic) */
    struct timespec  last_drop_time;    /**< Monotonic time of last cycle completion */
    uint32_t         min_gap_ms;        /**< Smallest cycle-to-cycle gap (ms)  */
    uint32_t         max_gap_ms;        /**< Largest cycle-to-cycle gap (ms)   */
    bool             has_gap_data;      /**< True after first gap recorded     */

    /* Sporadic timestamp capture (dynamic realloc, 1-second gate, no hard limit) */
    struct timespec  *suppress_ts;      /**< Heap-allocated timestamp array (µs precision) */
    uint16_t         ts_count;          /**< Number stored                     */
    uint16_t         ts_capacity;       /**< Allocated capacity                */
    time_t           last_stored_ts;    /**< For 1-second dedup gate (seconds only) */

    pthread_mutex_t  mutex;
} rdk_suppressor_state_t;

/* -----------------------------------------------------------------------
 * Return values for rdk_suppressor_process_message()
 * --------------------------------------------------------------------- */
typedef enum {
    RDK_SUPPRESS_LOG,      /**< Write this message normally                  */
    RDK_SUPPRESS_DROP,     /**< Discard silently — part of active pattern    */
    RDK_SUPPRESS_SUMMARY,  /**< Emit [SUPPRESS] summary, then write message  */
} rdk_suppress_action_t;

/* -----------------------------------------------------------------------
 * Config reader  (rdk_log_suppressor_config.c)
 * --------------------------------------------------------------------- */

/**
 * @brief Read RFC parameters from the INI config file and populate config.
 *
 * Reads from /nvram/rdk_log_suppressor.ini (RFC override) if it exists,
 * otherwise falls back to /etc/rdk_log_suppressor.ini (Yocto default).
 * Values outside valid ranges fall back to defaults with a WARNING
 * log (AC-5). Always emits an INFO log confirming the resolved state (AC-4).
 *
 * Must be called before rdk_suppressor_init().
 *
 * @param[out] config  Pointer to config struct to populate.
 */
void rdk_suppressor_read_config(rdk_suppressor_config_t *config);

/* -----------------------------------------------------------------------
 * Lifecycle  (rdk_log_suppressor_engine.c)
 * --------------------------------------------------------------------- */

/**
 * @brief Allocate buffers and initialise the engine mutex.
 *
 * Allocates history (2 * max_pattern_length entries) and pattern buffers
 * (max_pattern_length entries) from the heap. Must be called once at
 * rdk_dbg_priv_init() after rdk_suppressor_read_config().
 *
 * @param[in] config  Read-only config produced by rdk_suppressor_read_config().
 * @return 0 on success, -1 on allocation failure.
 */
int  rdk_suppressor_init(const rdk_suppressor_config_t *config);

/**
 * @brief Flush any active pattern summary and free all resources.
 *
 * Must be called at logger deinit. Flushes a pending [SUPPRESS] summary if
 * a pattern was active, then frees heap buffers and destroys the mutex.
 */
void rdk_suppressor_shutdown(void);

/* -----------------------------------------------------------------------
 * Hot path  (rdk_log_suppressor_engine.c)
 * --------------------------------------------------------------------- */

/**
 * @brief Process one log message through the suppressor.
 *
 * Called from rdk_dbg_priv_log_msg() for every message that passes the
 * log-level gate (AC-3). Acquires its own internal mutex — callers must
 * NOT hold g_suppressor_mutex when calling this.
 *
 * @param[in]  module_name  Logging module name.
 * @param[in]  message      Formatted message string.
 * @param[in]  level        Log level of the message.
 * @param[out] summary_out  If action == RDK_SUPPRESS_SUMMARY, this buffer
 *                          is populated with the [SUPPRESS] line to emit
 *                          before writing the current message.
 *                          Buffer must be at least RDK_SUPPRESSOR_MSG_SIZE bytes.
 * @param[out] ts_out       If non-NULL and event is sporadic, receives a
 *                          malloc'd timestamp line. Caller must free().
 * @return  Action the caller must take.
 */
rdk_suppress_action_t rdk_suppressor_process_message(
    const char  *module_name,
    const char  *message,
    rdk_LogLevel level,
    char        *summary_out,
    char       **ts_out);

#ifdef __cplusplus
}
#endif

#endif /* _RDK_LOG_SUPPRESSOR_H */
