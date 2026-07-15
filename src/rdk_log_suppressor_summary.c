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
 * @file rdk_log_suppressor_summary.c
 * @brief Formats [SUPPRESS] summary lines (AC-2).
 *
 * AC-2 format rules:
 *   Single-message pattern (pattern_length == 1):
 *     [SUPPRESS] "<message>" repeated N times (M messages suppressed for X seconds)
 *
 *   Multi-message pattern (pattern_length >= 2):
 *     [SUPPRESS] L-message pattern repeated N times (M messages suppressed for X seconds)
 *     followed by one breakdown line per pattern slot:
 *       Suppressed: "<message>" repeated N times
 *
 * The breakdown lines let T1 grep-based telemetry find and count an
 * individual pattern string, which never appears in the multi-message
 * header. The "repeated <n> times" token is the single machine-readable
 * count field shared by both the single-message header and the breakdown
 * lines, so one grep rule works for both: on a matching line, add the
 * number after "repeated"; otherwise count the line as one occurrence.
 *
 * Nothing is emitted if repeat_count == 0 — the caller is responsible for
 * only calling this when something was actually suppressed.
 */

#include "rdk_log_suppressor_summary.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <stdlib.h>

void rdk_suppressor_format_summary(
    const rdk_suppressor_state_t  *state,
    const rdk_suppressor_config_t *config,
    char                          *out,
    size_t                         out_sz,
    char                         **ts_out)
{
    if (ts_out)
        *ts_out = NULL;

    if (!state || !config || !out || out_sz == 0)
        return;

    out[0] = '\0';

    if (state->repeat_count == 0)
        return;

    double duration = difftime(state->last_timestamp, state->first_timestamp);
    unsigned int suppressed = state->repeat_count * (unsigned int)state->pattern_length;

    /* --- Timing classification --- */
    const char *behavior = "sporadic";
    char timing_detail[64] = "";
    bool have_real_gaps = (state->has_gap_data &&
                           state->repeat_count >= 2 &&
                           state->min_gap_ms != UINT32_MAX);

    if (have_real_gaps)
    {
        double avg_gap_s = ((double)state->min_gap_ms + state->max_gap_ms) / 2000.0;
        double rate = (avg_gap_s > 0) ? (double)state->pattern_length / avg_gap_s : 0;
        uint32_t safe_min = state->min_gap_ms ? state->min_gap_ms : 1;
        uint32_t ratio = state->max_gap_ms / safe_min;

        if (state->min_gap_ms < 100 && rate > 10)
        {
            behavior = "burst";
            snprintf(timing_detail, sizeof(timing_detail), "~%.0f msg/s", rate);
        }
        else if (ratio < 3)
        {
            behavior = "periodic";
            uint32_t avg_gap = (state->min_gap_ms + state->max_gap_ms) / 2;
            if (avg_gap >= 60000)
                snprintf(timing_detail, sizeof(timing_detail), "~every %umin", avg_gap / 60000);
            else if (avg_gap >= 1000)
                snprintf(timing_detail, sizeof(timing_detail), "~every %us", avg_gap / 1000);
            else
                snprintf(timing_detail, sizeof(timing_detail), "~every %ums", avg_gap);
        }
        else
        {
            behavior = "sporadic";
            if (duration >= 60)
                snprintf(timing_detail, sizeof(timing_detail), "over %.0f min", duration / 60.0);
            else
                snprintf(timing_detail, sizeof(timing_detail), "over %.0fs", duration);
        }
    }
    else if (duration > 0)
    {
        double rate = (double)suppressed / duration;
        if (rate > 10)
        {
            behavior = "burst";
            snprintf(timing_detail, sizeof(timing_detail), "~%.0f msg/s", rate);
        }
    }

    /* --- Format time window --- */
    struct tm start_tm, end_tm;
    char start_str[16], end_str[16];
    char window_str[48];
    localtime_r(&state->first_timestamp, &start_tm);
    localtime_r(&state->last_timestamp, &end_tm);
    snprintf(start_str, sizeof(start_str), "%02d:%02d:%02d",
             start_tm.tm_hour, start_tm.tm_min, start_tm.tm_sec);
    snprintf(end_str, sizeof(end_str), "%02d:%02d:%02d",
             end_tm.tm_hour, end_tm.tm_min, end_tm.tm_sec);

    if (state->first_timestamp == state->last_timestamp)
        snprintf(window_str, sizeof(window_str), "at %s", start_str);
    else
        snprintf(window_str, sizeof(window_str), "%s-%s", start_str, end_str);

    /* --- Build main summary line --- */
    if (state->pattern_length == 1)
    {
        /* Strip trailing newline from message for clean formatting */
        int msg_len = (int)strlen(state->pattern[0].message);
        while (msg_len > 0 && (state->pattern[0].message[msg_len - 1] == '\n' ||
                               state->pattern[0].message[msg_len - 1] == '\r'))
            msg_len--;

        snprintf(out, out_sz,
                 "[SUPPRESS] \"%.*s\" repeated %u times "
                 "(%s%s%s, %s)\n",
                 msg_len, state->pattern[0].message,
                 state->repeat_count,
                 behavior, timing_detail[0] ? " " : "", timing_detail,
                 window_str);
    }
    else
    {
        snprintf(out, out_sz,
                 "[SUPPRESS] %d-message pattern repeated %u times "
                 "(%s%s%s, %s)\n",
                 state->pattern_length,
                 state->repeat_count,
                 behavior, timing_detail[0] ? " " : "", timing_detail,
                 window_str);
    }

    /* --- For sporadic events, allocate timestamp line (caller frees) --- */
    if (ts_out && strcmp(behavior, "sporadic") == 0 && state->ts_count > 0)
    {
        /* Each timestamp = "HH:MM:SS.uuuuuu" (15) + ", " (2) = 17 chars
         * Date bracket "[MM-DD] " (8) added only when date changes
         * Worst case: all same day = 17 * count + 8 date changes */
        size_t buf_sz = 16 + (state->ts_count * 20) + 50;
        char *ts_line = (char *)malloc(buf_sz);
        if (ts_line)
        {
            int pos = 0;
            pos += snprintf(ts_line + pos, buf_sz - pos, "  At: ");
            int last_mday = -1, last_mon = -1;
            uint16_t i;
            for (i = 0; i < state->ts_count; i++)
            {
                struct tm ts_tm;
                time_t ts_sec = state->suppress_ts[i].tv_sec;
                long   ts_usec = state->suppress_ts[i].tv_nsec / 1000;
                localtime_r(&ts_sec, &ts_tm);

                /* Print date bracket only when date changes */
                if (ts_tm.tm_mday != last_mday || ts_tm.tm_mon != last_mon)
                {
                    if (i > 0)
                        pos += snprintf(ts_line + pos, buf_sz - pos, ", ");
                    pos += snprintf(ts_line + pos, buf_sz - pos, "[%02d-%02d] ",
                                    ts_tm.tm_mon + 1, ts_tm.tm_mday);
                    last_mday = ts_tm.tm_mday;
                    last_mon = ts_tm.tm_mon;
                }
                else
                {
                    if (i > 0)
                        pos += snprintf(ts_line + pos, buf_sz - pos, ", ");
                }

                pos += snprintf(ts_line + pos, buf_sz - pos, "%02d:%02d:%02d.%06ld",
                                ts_tm.tm_hour, ts_tm.tm_min, ts_tm.tm_sec, ts_usec);
            }
            snprintf(ts_line + pos, buf_sz - pos, "\n");
            *ts_out = ts_line;
        }
    }

    /* --- Multi-message: emit one breakdown line per pattern slot so T1
     *     grep-based telemetry can locate and count each individual pattern
     *     string (the strings never appear in the multi-message header).
     *     One line per slot is intentional: if the same string occupies
     *     several slots, grep sums them for the correct per-string count.
     *     Merged into *ts_out (after any sporadic "At:" line); the caller
     *     emits each '\n'-separated line as its own log record. --- */
    if (ts_out && state->pattern_length >= 2)
    {
        size_t existing_len = (*ts_out) ? strlen(*ts_out) : 0;
        size_t need = existing_len + 1;
        int p;
        for (p = 0; p < state->pattern_length; p++)
            need += strlen(state->pattern[p].message) + 64; /* wrapper + count */

        char *buf = (char *)malloc(need);
        if (buf)
        {
            int pos = 0;
            if (existing_len)
            {
                memcpy(buf, *ts_out, existing_len);
                pos = (int)existing_len;
            }
            for (p = 0; p < state->pattern_length; p++)
            {
                int mlen = (int)strlen(state->pattern[p].message);
                while (mlen > 0 && (state->pattern[p].message[mlen - 1] == '\n' ||
                                    state->pattern[p].message[mlen - 1] == '\r'))
                    mlen--;
                pos += snprintf(buf + pos, need - pos,
                                "  Suppressed: \"%.*s\" repeated %u times\n",
                                mlen, state->pattern[p].message,
                                state->repeat_count);
            }
            free(*ts_out);
            *ts_out = buf;
        }
    }
}
