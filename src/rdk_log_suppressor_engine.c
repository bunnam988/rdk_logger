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
 * @file rdk_log_suppressor_engine.c
 * @brief Circular-buffer pattern detection engine for RDK log suppressor.
 *
 * Algorithm (AC-1):
 *   On each eligible message M (already passed the log-level gate — AC-3):
 *
 *   1. If an active pattern exists:
 *      a. M matches pattern[next_expected_idx]?
 *         → Advance index. If full cycle completed, increment repeat_count.
 *           Return DROP.
 *      b. M does not match?
 *         → If repeat_count > 0: return SUMMARY (caller emits summary then logs M).
 *         → Else: reset pattern, fall through to step 2.
 *
 *   2. No active pattern — attempt detection:
 *      a. For L = 1 to max_pattern_length:
 *         - Need at least (2*L - 1) entries in history + current message.
 *         - Check history[0..L-1] == history[L..2L-1] (current = final entry).
 *         - For L >= 2: verify all L entries are distinct.
 *      b. Pattern found? Store it, set repeat_count = 0. Return LOG
 *         (this message completes the 2nd visible cycle).
 *      c. No pattern? Add to history. Return LOG.
 */

#include "rdk_log_suppressor.h"
#include "rdk_log_suppressor_summary.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

/* -----------------------------------------------------------------------
 * Module-level state
 * --------------------------------------------------------------------- */

static rdk_suppressor_config_t g_config;
static rdk_suppressor_state_t  g_state;
static bool                    g_initialized = false;

/* -----------------------------------------------------------------------
 * Fingerprint — FNV-1a 32-bit (same algorithm as POC, single-pass O(n))
 * --------------------------------------------------------------------- */
static uint32_t compute_fingerprint(const char *msg)
{
    if (!msg)
        return 0u;

    uint32_t hash = 2166136261u;
    const unsigned char *p = (const unsigned char *)msg;
    while (*p)
    {
        hash ^= *p++;
        hash *= 16777619u;
    }
    return hash;
}

/* -----------------------------------------------------------------------
 * Entry comparison — fingerprint-first O(1) rejection
 * --------------------------------------------------------------------- */
static bool entries_match(const rdk_log_entry_t *a, const rdk_log_entry_t *b)
{
    if (!a || !b)
        return false;
    if (a->fingerprint != b->fingerprint)
        return false;
    if (a->level != b->level)
        return false;
    if (strcmp(a->module_name, b->module_name) != 0)
        return false;
    return strcmp(a->message, b->message) == 0;
}

/* -----------------------------------------------------------------------
 * History buffer helpers
 * --------------------------------------------------------------------- */
static void history_add(const char *module_name, const char *message, rdk_LogLevel level)
{
    if (!message)
        return;

    int pos = g_state.history_head;
    rdk_log_entry_t *e = &g_state.history[pos];

    const char *mod = (module_name && *module_name) ? module_name : "";
    size_t mod_len = strlen(mod);
    if (mod_len >= sizeof(e->module_name))
        mod_len = sizeof(e->module_name) - 1;
    memcpy(e->module_name, mod, mod_len);
    e->module_name[mod_len] = '\0';

    size_t msg_len = strlen(message);
    if (msg_len >= sizeof(e->message))
        msg_len = sizeof(e->message) - 1;
    memcpy(e->message, message, msg_len);
    e->message[msg_len] = '\0';

    e->level       = level;
    e->fingerprint = compute_fingerprint(e->message);

    g_state.history_head = (pos + 1) % (int)g_config.history_buffer_size;
    if (g_state.history_count < (int)g_config.history_buffer_size)
        g_state.history_count++;
}

/* Returns entry at offset from most-recent (0 = most recent). NULL if invalid. */
static rdk_log_entry_t *history_get(int offset)
{
    if (offset < 0 || offset >= g_state.history_count ||
        offset >= (int)g_config.history_buffer_size)
        return NULL;

    int pos = (g_state.history_head - 1 - offset + (int)g_config.history_buffer_size)
              % (int)g_config.history_buffer_size;
    return &g_state.history[pos];
}

/* -----------------------------------------------------------------------
 * Pattern store helper
 * --------------------------------------------------------------------- */
static void pattern_store(int index, const rdk_log_entry_t *src)
{
    if (index < 0 || index >= (int)g_config.max_pattern_length || !src)
        return;

    g_state.pattern[index] = *src;  /* struct copy — src is already well-formed */
}

/* -----------------------------------------------------------------------
 * Pattern reset
 * --------------------------------------------------------------------- */
static void pattern_reset(void)
{
    g_state.pattern_length    = 0;
    g_state.next_expected_idx = 0;
    g_state.repeat_count      = 0;
    g_state.has_gap_data      = false;
    g_state.min_gap_ms        = UINT32_MAX;
    g_state.max_gap_ms        = 0;
    if (g_state.suppress_ts) {
        free(g_state.suppress_ts);
        g_state.suppress_ts = NULL;
    }
    g_state.ts_count          = 0;
    g_state.ts_capacity       = 0;
    g_state.last_stored_ts    = 0;
}

/* -----------------------------------------------------------------------
 * Pattern detection (returns detected length, 0 if none)
 * --------------------------------------------------------------------- */
static int try_detect_pattern(const rdk_log_entry_t *current)
{
    if (!current)
        return 0;

    /* --- Length 1: simplest case A A ... --- */
    rdk_log_entry_t *h0 = history_get(0);
    if (h0 && entries_match(current, h0))
    {
        pattern_store(0, h0);
        return 1;
    }

    /* --- Length 2 to max_pattern_length --- */
    for (int L = (int)g_config.max_pattern_length; L >= 2; L--)
    {
        int needed = 2 * L - 1;
        if (g_state.history_count < needed)
            continue;

        /* current must match history[L-1] */
        rdk_log_entry_t *anchor = history_get(L - 1);
        if (!anchor || !entries_match(current, anchor))
            continue;

        /* history[i] must match history[i+L] for i in [0, L-2] */
        bool ok = true;
        for (int i = 0; i < L - 1; i++)
        {
            rdk_log_entry_t *a = history_get(i);
            rdk_log_entry_t *b = history_get(i + L);
            if (!a || !b || !entries_match(a, b)) { ok = false; break; }
        }
        if (!ok)
            continue;

        /* All L elements must be distinct (prevents false "A A" → length-2) */
        rdk_log_entry_t *elems[RDK_SUPPRESSOR_MAX_PATTERN_LENGTH_LIMIT];
        bool valid = true;
        for (int i = 0; i < L; i++)
        {
            elems[i] = history_get(L - 1 - i);
            if (!elems[i]) { valid = false; break; }
        }
        if (!valid)
            continue;

        for (int i = 0; valid && i < L - 1; i++)
            for (int j = i + 1; valid && j < L; j++)
                if (entries_match(elems[i], elems[j]))
                    valid = false;

        if (!valid)
            continue;

        /* Store pattern: most-recent complete cycle */
        for (int i = 0; i < L - 1; i++)
        {
            rdk_log_entry_t *h = history_get(L - 2 - i);
            if (h) pattern_store(i, h);
        }
        pattern_store(L - 1, current);
        return L;
    }

    return 0;
}

/* -----------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------- */

int rdk_suppressor_init(const rdk_suppressor_config_t *config)
{
    if (!config)
        return -1;

    g_config = *config;

    if (!config->enabled)
    {
        g_initialized = true;
        return 0;
    }

    g_state.history = calloc(config->history_buffer_size, sizeof(rdk_log_entry_t));
    if (!g_state.history)
        return -1;

    g_state.pattern = calloc(config->max_pattern_length, sizeof(rdk_log_entry_t));
    if (!g_state.pattern)
    {
        free(g_state.history);
        g_state.history = NULL;
        return -1;
    }

    g_state.history_head      = 0;
    g_state.history_count     = 0;
    g_state.pattern_length    = 0;
    g_state.next_expected_idx = 0;
    g_state.repeat_count      = 0;
    g_state.first_timestamp   = 0;
    g_state.last_timestamp    = 0;
    g_state.has_gap_data      = false;
    g_state.min_gap_ms        = UINT32_MAX;
    g_state.max_gap_ms        = 0;
    g_state.suppress_ts       = NULL;
    g_state.ts_count          = 0;
    g_state.ts_capacity       = 0;
    g_state.last_stored_ts    = 0;
    pthread_mutex_init(&g_state.mutex, NULL);

    g_initialized = true;
    return 0;
}

void rdk_suppressor_shutdown(void)
{
    if (!g_initialized || !g_config.enabled)
        return;

    pthread_mutex_lock(&g_state.mutex);

    /* Flush any active summary before freeing */
    if (g_state.pattern_length > 0 && g_state.repeat_count > 0)
    {
        char summary[RDK_SUPPRESSOR_MSG_SIZE];
        char *ts_line = NULL;
        rdk_suppressor_format_summary(&g_state, &g_config, summary, sizeof(summary), &ts_line);
        /* Use fprintf since log4c may already be torn down */
        fprintf(stderr, "%s", summary);
        if (ts_line) {
            fprintf(stderr, "%s", ts_line);
            free(ts_line);
        }
    }

    free(g_state.history);
    free(g_state.pattern);
    free(g_state.suppress_ts);
    g_state.history = NULL;
    g_state.pattern = NULL;
    g_state.suppress_ts = NULL;

    pthread_mutex_unlock(&g_state.mutex);
    pthread_mutex_destroy(&g_state.mutex);

    g_initialized = false;
}

rdk_suppress_action_t rdk_suppressor_process_message(
    const char  *module_name,
    const char  *message,
    rdk_LogLevel level,
    char        *summary_out,
    char       **ts_out)
{
    if (ts_out)
        *ts_out = NULL;

    if (!g_initialized || !g_config.enabled || !message)
        return RDK_SUPPRESS_LOG;

    /* Prepare current entry — use memcpy to avoid strncpy zero-fill overhead */
    rdk_log_entry_t cur;
    const char *mod = (module_name && *module_name) ? module_name : "";
    size_t mod_len = strlen(mod);
    if (mod_len >= sizeof(cur.module_name))
        mod_len = sizeof(cur.module_name) - 1;
    memcpy(cur.module_name, mod, mod_len);
    cur.module_name[mod_len] = '\0';

    size_t msg_len = strlen(message);
    if (msg_len >= sizeof(cur.message))
        msg_len = sizeof(cur.message) - 1;
    memcpy(cur.message, message, msg_len);
    cur.message[msg_len] = '\0';

    cur.level       = level;
    cur.fingerprint = compute_fingerprint(cur.message);

    time_t now = time(NULL);
    if (now == (time_t)(-1))
        now = 0;

    pthread_mutex_lock(&g_state.mutex);

    rdk_suppress_action_t action = RDK_SUPPRESS_LOG;

    if (g_state.pattern_length > 0)
    {
        /* Validate state integrity */
        if (g_state.pattern_length > (int)g_config.max_pattern_length ||
            g_state.next_expected_idx < 0 ||
            g_state.next_expected_idx >= g_state.pattern_length)
        {
            pattern_reset();
            /* Fall through to detection below */
        }
        else
        {
            rdk_log_entry_t *expected = &g_state.pattern[g_state.next_expected_idx];

            if (entries_match(&cur, expected))
            {
                /* Message continues active pattern — suppress it (AC-1) */
                g_state.last_timestamp = now;

                /* Store cycle-start timestamp (1-second gate to skip bursts) */
                int cur_idx = g_state.next_expected_idx;
                if (cur_idx == 0 &&
                    (g_state.ts_count == 0 || difftime(now, g_state.last_stored_ts) >= 1.0))
                {
                    if (g_state.ts_count >= g_state.ts_capacity)
                    {
                        uint16_t new_cap = g_state.ts_capacity ? g_state.ts_capacity * 2 : 16;
                        if (new_cap <= g_state.ts_capacity)
                            new_cap = UINT16_MAX; /* overflow guard: cap at 65535 */
                        time_t *tmp = realloc(g_state.suppress_ts, new_cap * sizeof(time_t));
                        if (tmp) {
                            g_state.suppress_ts = tmp;
                            g_state.ts_capacity = new_cap;
                        }
                    }
                    if (g_state.ts_count < g_state.ts_capacity)
                    {
                        g_state.suppress_ts[g_state.ts_count++] = now;
                        g_state.last_stored_ts = now;
                    }
                }

                g_state.next_expected_idx = (cur_idx + 1)
                                             % g_state.pattern_length;
                if (g_state.next_expected_idx == 0)
                {
                    /* Cycle completed — track gap for timing classification */
                    struct timespec now_mono;
                    clock_gettime(CLOCK_MONOTONIC_COARSE, &now_mono);
                    if (g_state.has_gap_data)
                    {
                        uint32_t gap_ms = (uint32_t)(
                            (now_mono.tv_sec - g_state.last_drop_time.tv_sec) * 1000 +
                            (now_mono.tv_nsec - g_state.last_drop_time.tv_nsec) / 1000000);
                        if (gap_ms < g_state.min_gap_ms)
                            g_state.min_gap_ms = gap_ms;
                        if (gap_ms > g_state.max_gap_ms)
                            g_state.max_gap_ms = gap_ms;
                    }
                    else
                    {
                        g_state.min_gap_ms = UINT32_MAX;
                        g_state.max_gap_ms = 0;
                        g_state.has_gap_data = true;
                    }
                    g_state.last_drop_time = now_mono;

                    if (g_state.repeat_count < UINT_MAX)
                        g_state.repeat_count++;
                }
                /* Skip history_add on DROP path — suppressed messages never
                 * contribute to detecting a new pattern (saves ~1KB per drop) */
                pthread_mutex_unlock(&g_state.mutex);
                return RDK_SUPPRESS_DROP;
            }
            else
            {
                /* Pattern broken */
                if (g_state.repeat_count > 0)
                {
                    /* Build summary before reset (AC-2) */
                    if (summary_out)
                        rdk_suppressor_format_summary(&g_state, &g_config,
                                                      summary_out, RDK_SUPPRESSOR_MSG_SIZE,
                                                      ts_out);
                    pattern_reset();
                    /* Detect new pattern from history + current */
                    int L = try_detect_pattern(&cur);
                    if (L > 0)
                    {
                        g_state.pattern_length    = L;
                        g_state.next_expected_idx = 0;
                        g_state.repeat_count      = 0;
                        g_state.first_timestamp   = now;
                        g_state.last_timestamp    = now;
                    }
                    else
                    {
                        pattern_reset();
                    }
                    history_add(mod, message, level);
                    pthread_mutex_unlock(&g_state.mutex);
                    return RDK_SUPPRESS_SUMMARY;
                }
                else
                {
                    /* Pattern detected but never repeated — just reset and re-evaluate */
                    pattern_reset();
                    /* Fall through to detection below */
                }
            }
        }
    }

    /* No active pattern — try to detect one */
    int L = try_detect_pattern(&cur);
    if (L > 0)
    {
        g_state.pattern_length    = L;
        g_state.next_expected_idx = 0;
        g_state.repeat_count      = 0;
        g_state.first_timestamp   = now;
        g_state.last_timestamp    = now;
    }
    else
    {
        pattern_reset();
    }

    history_add(mod, message, level);
    action = RDK_SUPPRESS_LOG;

    pthread_mutex_unlock(&g_state.mutex);
    return action;
}
