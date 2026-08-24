###############################################################################
#
# Access Audit - Aggregate Export
#
# Generates compact aggregation data from a single audit.
#
# The aggregate file is intended to be consumed by:
#
#     domain -> configuration -> machine -> global
#
# Only TOP 50 ranking entries are exported.
# Percentages are deliberately NOT exported; they are recalculated by the
# collector at each aggregation level.
#
###############################################################################


###############################################################################
# CONFIGURATION
###############################################################################

BEGIN {
    AGG_TOP = 50
}


###############################################################################
# ESCAPE
###############################################################################

function agg_escape(value,    s)
{
    s = value

    gsub(/\\/, "\\\\", s)
    gsub(/"/, "\\\"", s)
    gsub(/\r/, "\\r", s)
    gsub(/\n/, "\\n", s)
    gsub(/\t/, "\\t", s)

    return s
}


###############################################################################
# WRITE RANKING
###############################################################################

function aggregate_ranking(name, array,    sorted, n, limit, i, key)
{
    n = sort_by_hits(array, sorted)

    limit = AGG_TOP

    if (limit > n)
        limit = n

    for (i = 1; i <= limit; i++)
    {
        key = sorted[i]

        if (key == "")
            continue

        printf "%s|%s|%d\n",
               name,
               agg_escape(key),
               array[key] > AGG_FILE
    }
}


###############################################################################
# WRITE SLOWEST REQUESTS
###############################################################################

function aggregate_slowest(    sorted, n, limit, i, key)
{
    n = asorti(slow_time, sorted, "@val_num_desc")

    limit = AGG_TOP

    if (limit > n)
        limit = n

    for (i = 1; i <= limit; i++)
    {
        key = sorted[i]

        if (key == "")
            continue

        printf "slow|%.3f|%s|%d|%s|%s|%s|%s\n",
               slow_time[key] / 1000000,
               agg_escape(slow_ip[key]),
               slow_status[key],
               agg_escape(slow_method[key]),
               agg_escape(slow_url[key]),
               agg_escape(slow_host[key]),
               agg_escape(slow_timestamp[key]) > AGG_FILE
    }
}


###############################################################################
# WRITE ATTACKS
###############################################################################

function aggregate_attacks(    sorted, n, i, key)
{
    n = sort_by_hits(stat_attack, sorted)

    for (i = 1; i <= n; i++)
    {
        key = sorted[i]

        if (key == "")
            continue

        printf "attack|%s|%d|%s|%s|%s\n",
               agg_escape(key),
               stat_attack[key],
               agg_escape(attack_example[key]),
               agg_escape(attack_ip[key]),
               agg_escape(attack_timestamp[key]) > AGG_FILE
    }
}


###############################################################################
# WRITE AGGREGATE
###############################################################################

function write_aggregate()
{
    ###########################################################################
    # METADATA
    ###########################################################################

    printf "date|%s\n",
           agg_escape(AUDIT_DATE) > AGG_FILE

    printf "configuration|%s\n",
           agg_escape(AUDIT_CONFIGURATION) > AGG_FILE

    printf "title|%s\n",
           agg_escape(AUDIT_TITLE) > AGG_FILE


    ###########################################################################
    # REQUEST TOTALS
    ###########################################################################

    printf "total|requests|%d\n",
           stat_requests > AGG_FILE

    printf "total|errors|%d\n",
           stat_errors > AGG_FILE

    printf "total|bytes|%d\n",
           stat_total_bytes > AGG_FILE

    printf "total|search_requests|%d\n",
           stat_search_requests > AGG_FILE


    ###########################################################################
    # LATENCY
    ###########################################################################

    printf "latency|total_us|%d\n",
           stat_total_time > AGG_FILE

    printf "latency|min_us|%d\n",
           stat_min_time > AGG_FILE

    printf "latency|max_us|%d\n",
           stat_max_time > AGG_FILE


    ###########################################################################
    # SECURITY
    ###########################################################################

    printf "security|bot_requests|%d\n",
           stat_bot_requests > AGG_FILE

    printf "security|human_requests|%d\n",
           stat_human_requests > AGG_FILE

    printf "security|automatic_requests|%d\n",
           stat_aut_requests > AGG_FILE


    ###########################################################################
    # UNIQUE COUNTERS
    #
    # These cannot simply be summed between domains.
    # They are exported for reference, but the machine/configuration collector
    # should NOT calculate global unique values by summing these numbers.
    ###########################################################################

    printf "unique|ips|%d\n",
           stat_unique_ips > AGG_FILE

    printf "unique|hosts|%d\n",
           stat_unique_hosts > AGG_FILE

    printf "unique|urls|%d\n",
           stat_unique_urls > AGG_FILE

    printf "unique|user_agents|%d\n",
           stat_unique_useragents > AGG_FILE

    printf "unique|methods|%d\n",
           stat_unique_methods > AGG_FILE

    printf "unique|referers|%d\n",
           stat_unique_referers > AGG_FILE

    printf "unique|extensions|%d\n",
           stat_unique_extensions > AGG_FILE


    ###########################################################################
    # RANKINGS
    ###########################################################################

    aggregate_ranking("ip",          stat_ip)
    aggregate_ranking("status",      stat_status)
    aggregate_ranking("host",        stat_host)
    aggregate_ranking("url",         stat_url)
    aggregate_ranking("search",      search_urls)
    aggregate_ranking("user_agent",  stat_useragent)
    aggregate_ranking("method",      stat_method)
    aggregate_ranking("referer",     stat_referer)
    aggregate_ranking("extension",   stat_extension)
    aggregate_ranking("bot",         stat_bot)
    aggregate_ranking("automation",  stat_automation)


    ###########################################################################
    # SLOWEST REQUESTS
    ###########################################################################

    aggregate_slowest()


    ###########################################################################
    # ATTACKS
    ###########################################################################

    aggregate_attacks()


    ###########################################################################
    # END MARKER
    ###########################################################################

    print "end" > AGG_FILE

    close(AGG_FILE)
}
