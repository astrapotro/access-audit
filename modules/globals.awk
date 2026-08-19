BEGIN {

    DEFAULT_TOP=20

    JSON_TOP=50

    FORMAT="Ejie"

    FS="\n"

    init()

}

###############################################################################
# INITIALIZATION
###############################################################################

function init()
{
    top_limit=DEFAULT_TOP

    stat_requests=0
    stat_total_bytes=0
    stat_total_time=0

    stat_unique_ips=0
    stat_unique_hosts=0
    stat_unique_urls=0
    stat_unique_useragents=0
    stat_unique_methods=0
    stat_unique_referers=0
    stat_unique_extensions=0

    stat_min_time = 0
    stat_max_time = 0

    stat_bot_requests = 0
    stat_human_requests = 0
    stat_aut_requests = 0

##    stat_bot[bot_name]++
##    stat_automation[client]++

}
