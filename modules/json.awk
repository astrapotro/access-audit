###############################################################################
# JSON EXPORT
###############################################################################

function json_escape(value,    s)
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
# RANKING JSON
###############################################################################

function json_ranking(array, limit,    sorted, n, i, key, first)
{
    n = sort_by_hits(array, sorted)

    if (limit > n)
        limit = n

    first = 1

    print "[" > JSON_FILE

    for (i = 1; i <= limit; i++)
    {
        key = sorted[i]

        if (key == "")
            continue

        if (!first)
            print "," > JSON_FILE

        printf "    {\"value\":\"%s\",\"hits\":%d,\"percent\":%.3f}",
               json_escape(key),
               array[key],
               percent(array[key]) + 0 > JSON_FILE

        first = 0
    }

    print "" > JSON_FILE
    print "    ]" > JSON_FILE
}


###############################################################################
# ATAQUES JSON
###############################################################################

function json_attacks(    sorted, n, i, key, first)
{
    n = sort_by_hits(stat_attack, sorted)

    first = 1

    print "[" > JSON_FILE

    for (i = 1; i <= n; i++)
    {
        key = sorted[i]

        if (key == "")
            continue

        if (!first)
            print "," > JSON_FILE

        printf "    {" > JSON_FILE

        printf "\"indicator\":\"%s\",",
               json_escape(key) > JSON_FILE

        printf "\"hits\":%d,",
               stat_attack[key] > JSON_FILE

        printf "\"example\":\"%s\",",
               json_escape(attack_example[key]) > JSON_FILE

        printf "\"ip\":\"%s\",",
               json_escape(attack_ip[key]) > JSON_FILE

        printf "\"timestamp\":\"%s\"",
               json_escape(attack_timestamp[key]) > JSON_FILE

        printf "}" > JSON_FILE

        first = 0
    }

    print "" > JSON_FILE
    print "    ]" > JSON_FILE
}


###############################################################################
# EXPORT PRINCIPAL
###############################################################################

function print_json(    top)
{
    top = JSON_TOP

    ###########################################################################
    # Información del análisis
    ###########################################################################

    print "{" > JSON_FILE

    printf "  \"date\":\"%s\",\n",
           json_escape(AUDIT_DATE) > JSON_FILE

    printf "  \"source\":\"%s\",\n",
           json_escape(AUDIT_SOURCE) > JSON_FILE

    printf "  \"file\":\"%s\",\n",
           json_escape(AUDIT_FILE) > JSON_FILE

    printf "  \"configuration\":\"%s\",\n",
           json_escape(AUDIT_CONFIGURATION) > JSON_FILE

    printf "  \"title\":\"%s\",\n",
           json_escape(AUDIT_TITLE) > JSON_FILE


    ###########################################################################
    # PETICIONES
    ###########################################################################

    print "  \"requests\": {" > JSON_FILE

    printf "    \"total\":%d,\n",
           stat_requests > JSON_FILE

    printf "    \"errors\":%d,\n",
           stat_errors > JSON_FILE

    printf "    \"bytes\":%d,\n",
           stat_total_bytes > JSON_FILE

    printf "    \"search requests\":%d,\n",
           stat_search_requests > JSON_FILE

    print "    \"unique\": {" > JSON_FILE

    printf "      \"ips\":%d,\n",
           stat_unique_ips > JSON_FILE

    printf "      \"hosts\":%d,\n",
           stat_unique_hosts > JSON_FILE

    printf "      \"urls\":%d,\n",
           stat_unique_urls > JSON_FILE

    printf "      \"user_agents\":%d,\n",
           stat_unique_useragents > JSON_FILE

    printf "      \"methods\":%d,\n",
           stat_unique_methods > JSON_FILE

    printf "      \"referers\":%d,\n",
           stat_unique_referers > JSON_FILE

    printf "      \"extensions\":%d\n",
           stat_unique_extensions > JSON_FILE

    print "    }" > JSON_FILE
    print "  }," > JSON_FILE


    ###########################################################################
    # LATENCIA
    ###########################################################################

    print "  \"latency\": {" > JSON_FILE

    printf "    \"total_us\":%d,\n",
           stat_total_time > JSON_FILE

    if (stat_requests > 0)
    {
        printf "    \"avg_ms\":%.3f,\n",
               stat_total_time / stat_requests / 1000 > JSON_FILE

        printf "    \"min_ms\":%.3f,\n",
               stat_min_time / 1000 > JSON_FILE

        printf "    \"max_ms\":%.3f\n",
               stat_max_time / 1000 > JSON_FILE
    }
    else
    {
        print "    \"avg_ms\":0," > JSON_FILE
        print "    \"min_ms\":0," > JSON_FILE
        print "    \"max_ms\":0" > JSON_FILE
    }

    print "  }," > JSON_FILE


    ###########################################################################
    # SEGURIDAD
    ###########################################################################

    print "  \"security\": {" > JSON_FILE

    printf "    \"bot_requests\":%d,\n",
           stat_bot_requests > JSON_FILE

    printf "    \"human_requests\":%d,\n",
           stat_human_requests > JSON_FILE

    printf "    \"automatic_requests\":%d\n",
           stat_aut_requests > JSON_FILE

    print "  }," > JSON_FILE


    ###########################################################################
    # RANKINGS
    ###########################################################################

    print "  \"rankings\": {" > JSON_FILE

    print "    \"limit\":50," > JSON_FILE


    printf "    \"ips\":" > JSON_FILE
    json_ranking(stat_ip, top)
    print "," > JSON_FILE


    printf "    \"status\":" > JSON_FILE
    json_ranking(stat_status, top)
    print "," > JSON_FILE


    printf "    \"hosts\":" > JSON_FILE
    json_ranking(stat_host, top)
    print "," > JSON_FILE


    printf "    \"urls\":" > JSON_FILE
    json_ranking(stat_url, top)
    print "," > JSON_FILE


    printf "    \"search\":" > JSON_FILE
    json_search_ranking(search_urls, top)
    print "," > JSON_FILE


    printf "    \"user_agents\":" > JSON_FILE
    json_ranking(stat_useragent, top)
    print "," > JSON_FILE


    printf "    \"methods\":" > JSON_FILE
    json_ranking(stat_method, top)
    print "," > JSON_FILE


    printf "    \"referers\":" > JSON_FILE
    json_ranking(stat_referer, top)
    print "," > JSON_FILE


    printf "    \"extensions\":" > JSON_FILE
    json_ranking(stat_extension, top)
    print "," > JSON_FILE


    printf "    \"bots\":" > JSON_FILE
    json_ranking(stat_bot, top)
    print "," > JSON_FILE


    printf "    \"automation\":" > JSON_FILE
    json_ranking(stat_automation, top)
    print "," > JSON_FILE


    printf "    \"slowest_requests\":" > JSON_FILE
    json_slowest_requests(top)

    print "  }," > JSON_FILE


    ###########################################################################
    # ATAQUES
    ###########################################################################

    print "  \"attacks\":" > JSON_FILE

    json_attacks()

    print "}" > JSON_FILE

    close(JSON_FILE)

}


###############################################################################
# SLOWEST REQUESTS JSON
###############################################################################

function json_slowest_requests(limit,
                               sorted, n, i, key, first)
{
    n = asorti(slow_time, sorted, "@val_num_desc")

    if (limit > n)
        limit = n

    first = 1

    print "[" > JSON_FILE

    for (i = 1; i <= limit; i++)
    {
        key = sorted[i]

        if (key == "")
            continue

        if (!first)
            print "," > JSON_FILE

        printf "    {" > JSON_FILE

        printf "\"time_s\":%.3f,",
               slow_time[key] / 1000000 > JSON_FILE

        printf "\"ip\":\"%s\",",
               json_escape(slow_ip[key]) > JSON_FILE

        printf "\"status\":%d,",
               slow_status[key] > JSON_FILE

        printf "\"method\":\"%s\",",
               json_escape(slow_method[key]) > JSON_FILE

        printf "\"url\":\"%s\",",
               json_escape(slow_url[key]) > JSON_FILE

        printf "\"host\":\"%s\",",
               json_escape(slow_host[key]) > JSON_FILE

        printf "\"timestamp\":\"%s\"",
               json_escape(slow_timestamp[key]) > JSON_FILE

        printf "}" > JSON_FILE

        first = 0
    }

    print "" > JSON_FILE
    print "    ]" > JSON_FILE
}

###############################################################################
# SEARCH RANKING JSON
###############################################################################

function json_search_ranking(array, limit,    sorted, n, i, key, first)
{
    n = sort_by_hits(array, sorted)

    if (limit > n)
        limit = n

    first = 1

    print "[" > JSON_FILE

    for (i = 1; i <= limit; i++)
    {
        key = sorted[i]

        if (key == "")
            continue

        if (!first)
            print "," > JSON_FILE

        printf "    {\"value\":\"%s\",\"hits\":%d,\"percent\":%.3f}",
               json_escape(key),
               array[key],
               stat_search_requests ?
                   (array[key] / stat_search_requests) * 100 : 0 > JSON_FILE

        first = 0
    }

    print "" > JSON_FILE
    print "    ]" > JSON_FILE
}


