#ifndef POC_EVENT_LOGIC_H
#define POC_EVENT_LOGIC_H
#include "event.h"

static inline void poc_process_event(const struct poc_event *event,
                                     poc_u32 target, struct poc_stats *stats)
{
    if (event->version != POC_EVENT_VERSION || event->type != POC_EVENT_GETPID ||
        event->event_bytes != POC_EVENT_BYTES || event->tgid != target ||
        event->pid != target || !event->timestamp_ns || event->flags ||
        !event->seq || event->seq <= stats->last_seq) {
        ++stats->format_rejected;
        return;
    }
    for (unsigned int i = 0; i < sizeof(event->reserved); ++i) {
        if (event->reserved[i]) {
            ++stats->format_rejected;
            return;
        }
    }
    stats->last_seq = event->seq;
    ++stats->processed;
    if (event->tgid == target && event->type == POC_EVENT_GETPID)
        ++stats->matched;
}
#endif
