###############################################################################
#
# Access Audit - Machine Collector
#
###############################################################################
#
# Input:
#
#   access-audit-YYYY-MM-DD.json
#
# The corresponding aggregate file is expected next to the JSON:
#
#   access-audit-YYYY-MM-DD.agg
#
###############################################################################


###############################################################################
# CONFIGURATION
###############################################################################

BEGIN
{
    TOP = 50

    current_configuration = ""

    first_configuration = 1
    first_domain = 1
}


###############################################################################
# JSON ESCAPE
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
# READ FILE
###############################################################################

function read_file(filename,    line, content)
{
    content = ""

    while ((getline line < filename) > 0)
        content = content line "\n"

    close(filename)

    return content
}


###############################################################################
# RESET CONFIGURATION
###############################################################################

function reset_configuration()
{
    delete conf_total
    delete conf_latency
    delete conf_security
    delete conf_rank

    delete conf_slow_time
    delete conf_slow_ip
    delete conf_slow_status
    delete conf_slow_method
    delete conf_slow_url
    delete conf_slow_host
    delete conf_slow_timestamp
    conf_slow_count = 0

    delete conf_attack_hits
    delete conf_attack_example
    delete conf_attack_ip
    delete conf_attack_timestamp
}


###############################################################################
# RESET MACHINE
###############################################################################

function reset_machine()
{
    delete machine_total
    delete machine_latency
    delete machine_security
    delete machine_rank

    delete machine_slow_time
    delete machine_slow_ip
    delete machine_slow_status
    delete machine_slow_method
    delete machine_slow_url
    delete machine_slow_host
    delete machine_slow_timestamp
    machine_slow_count = 0

    delete machine_attack_hits
    delete machine_attack_example
    delete machine_attack_ip
    delete machine_attack_timestamp
}


###############################################################################
# ADD RANKING
###############################################################################

function add_ranking(array, type, value, hits)
{
    if (value == "")
        return

    array[type SUBSEP value] += hits
}


###############################################################################
# ADD SLOW REQUEST
###############################################################################

function add_slow(prefix, time_s, ip, status, method, url, host, timestamp,    n)
{
    if (prefix == "conf")
    {
        n = ++conf_slow_count

        conf_slow_time[n] = time_s
        conf_slow_ip[n] = ip
        conf_slow_status[n] = status
        conf_slow_method[n] = method
        conf_slow_url[n] = url
        conf_slow_host[n] = host
        conf_slow_timestamp[n] = timestamp
    }
    else
    {
        n = ++machine_slow_count

        machine_slow_time[n] = time_s
        machine_slow_ip[n] = ip
        machine_slow_status[n] = status
        machine_slow_method[n] = method
        machine_slow_url[n] = url
        machine_slow_host[n] = host
        machine_slow_timestamp[n] = timestamp
    }
}


###############################################################################
# ADD ATTACK
###############################################################################

function add_attack(prefix, indicator, hits, example, ip, timestamp)
{
    if (indicator == "")
        return

    if (prefix == "conf")
    {
        conf_attack_hits[indicator] += hits

        if (!(indicator in conf_attack_example))
        {
            conf_attack_example[indicator] = example
            conf_attack_ip[indicator] = ip
            conf_attack_timestamp[indicator] = timestamp
        }
    }
    else
    {
        machine_attack_hits[indicator] += hits

        if (!(indicator in machine_attack_example))
        {
            machine_attack_example[indicator] = example
            machine_attack_ip[indicator] = ip
            machine_attack_timestamp[indicator] = timestamp
        }
    }
}


###############################################################################
# PROCESS AGGREGATE
###############################################################################

function process_aggregate(filename,    line, f, type, name, value, hits)
{
    #
    # If the aggregate file does not exist, simply return.
    #
    if ((getline line < filename) < 0)
    {
        close(filename)
        return
    }

    #
    # Process first line and remaining lines.
    #
    do
    {
        if (line == "")
            continue

        split(line, f, "|")

        type = f[1]


        #######################################################################
        # TOTALS
        #######################################################################

        if (type == "total")
        {
            name = f[2]
            value = f[3] + 0

            conf_total[name] += value
            machine_total[name] += value

            continue
        }


        #######################################################################
        # LATENCY
        #######################################################################

        if (type == "latency")
        {
            name = f[2]
            value = f[3] + 0

            conf_latency[name] += value
            machine_latency[name] += value

            continue
        }


        #######################################################################
        # SECURITY
        #######################################################################

        if (type == "security")
        {
            name = f[2]
            value = f[3] + 0

            conf_security[name] += value
            machine_security[name] += value

            continue
        }


        #######################################################################
        # UNIQUE
        #
        # Deliberately ignored at configuration/machine level.
        #
        # They cannot be summed because the same IP/URL/etc. can occur in
        # several domains.
        #######################################################################

        if (type == "unique")
            continue


        #######################################################################
        # RANKINGS
        #######################################################################

        if (type == "ip" ||
            type == "status" ||
            type == "host" ||
            type == "url" ||
            type == "search" ||
            type == "user_agent" ||
            type == "method" ||
            type == "referer" ||
            type == "extension" ||
            type == "bot" ||
            type == "automation")
        {
            value = f[2]
            hits = f[3] + 0

            add_ranking(conf_rank, type, value, hits)
            add_ranking(machine_rank, type, value, hits)

            continue
        }


        #######################################################################
        # SLOWEST REQUESTS
        #######################################################################

        if (type == "slow")
        {
            add_slow(
                "conf",
                f[2] + 0,
                f[3],
                f[4] + 0,
                f[5],
                f[6],
                f[7],
                f[8]
            )

            add_slow(
                "machine",
                f[2] + 0,
                f[3],
                f[4] + 0,
                f[5],
                f[6],
                f[7],
                f[8]
            )

            continue
        }


        #######################################################################
        # ATTACKS
        #######################################################################

        if (type == "attack")
        {
            add_attack(
                "conf",
                f[2],
                f[3] + 0,
                f[4],
                f[5],
                f[6]
            )

            add_attack(
                "machine",
                f[2],
                f[3] + 0,
                f[4],
                f[5],
                f[6]
            )

            continue
        }

    }
    while ((getline line < filename) > 0)

    close(filename)
}


###############################################################################
# GET RANKING VALUES
###############################################################################

function collect_ranking(array, type, values, hits,
                          key, value, n)
{
    delete values
    delete hits

    n = 0

    for (key in array)
    {
        if (index(key, type SUBSEP) == 1)
        {
            value = substr(key, length(type) + 2)

            values[++n] = value
            hits[value] = array[key]
        }
    }

    return n
}


###############################################################################
# SORT RANKING
###############################################################################

function sort_ranking(values, hits, n,    i, j, tmp)
{
    #
    # TOP 50 only.
    #
    # Selection-style sorting is enough here because the number of distinct
    # entries comes from the TOP 50 of each domain.
    #

    for (i = 1; i <= n; i++)
    {
        for (j = i + 1; j <= n; j++)
        {
            if (hits[values[j]] > hits[values[i]])
            {
                tmp = values[i]
                values[i] = values[j]
                values[j] = tmp
            }
        }
    }
}


###############################################################################
# PRINT RANKING
###############################################################################

function print_ranking(array, type, total,
                       values, hits, n, limit, i, value, first)
{
    n = collect_ranking(array, type, values, hits)

    sort_ranking(values, hits, n)

    limit = n

    if (limit > TOP)
        limit = TOP

    print "["

    first = 1

    for (i = 1; i <= limit; i++)
    {
        value = values[i]

        if (!first)
            print ","

        printf "        {\"value\":\"%s\",\"hits\":%d,\"percent\":%.3f}",
               json_escape(value),
               hits[value],
               total > 0 ? (hits[value] / total) * 100 : 0

        first = 0
    }

    print ""
    print "      ]"
}


###############################################################################
# PRINT RANKINGS
###############################################################################

function print_rankings(array, total)
{
    print "    \"rankings\": {"

    print "      \"limit\":50,"

    printf "      \"ips\":"
    print_ranking(array, "ip", total)
    print ","

    printf "      \"status\":"
    print_ranking(array, "status", total)
    print ","

    printf "      \"hosts\":"
    print_ranking(array, "host", total)
    print ","

    printf "      \"urls\":"
    print_ranking(array, "url", total)
    print ","

    printf "      \"search\":"
    print_ranking(array, "search", total)
    print ","

    printf "      \"user_agents\":"
    print_ranking(array, "user_agent", total)
    print ","

    printf "      \"methods\":"
    print_ranking(array, "method", total)
    print ","

    printf "      \"referers\":"
    print_ranking(array, "referer", total)
    print ","

    printf "      \"extensions\":"
    print_ranking(array, "extension", total)
    print ","

    printf "      \"bots\":"
    print_ranking(array, "bot", total)
    print ","

    printf "      \"automation\":"
    print_ranking(array, "automation", total)

    print "    },"
}


###############################################################################
# PRINT TOTALS
###############################################################################

function print_totals(total)
{
    print "    \"requests\": {"

    printf "      \"total\":%d,\n",
           total["requests"]

    printf "      \"errors\":%d,\n",
           total["errors"]

    printf "      \"bytes\":%d,\n",
           total["bytes"]

    printf "      \"search requests\":%d\n",
           total["search_requests"]

    print "    },"
}


###############################################################################
# PRINT LATENCY
###############################################################################

function print_latency(latency, requests)
{
    print "    \"latency\": {"

    printf "      \"total_us\":%d,\n",
           latency["total_us"]

    if (requests > 0)
    {
        printf "      \"avg_ms\":%.3f,\n",
               latency["total_us"] / requests / 1000

        printf "      \"min_ms\":%.3f,\n",
               latency["min_us"] / 1000

        printf "      \"max_ms\":%.3f\n",
               latency["max_us"] / 1000
    }
    else
    {
        print "      \"avg_ms\":0,"
        print "      \"min_ms\":0,"
        print "      \"max_ms\":0"
    }

    print "    },"
}


###############################################################################
# PRINT SECURITY
###############################################################################

function print_security(security)
{
    print "    \"security\": {"

    printf "      \"bot_requests\":%d,\n",
           security["bot_requests"]

    printf "      \"human_requests\":%d,\n",
           security["human_requests"]

    printf "      \"automatic_requests\":%d\n",
           security["automatic_requests"]

    print "    },"
}


###############################################################################
# PRINT SLOWEST REQUESTS
###############################################################################

function print_slowest(prefix)
{
    if (prefix == "conf")
    {
        count = conf_slow_count
        time = conf_slow_time
        ip = conf_slow_ip
        status = conf_slow_status
        method = conf_slow_method
        url = conf_slow_url
        host = conf_slow_host
        timestamp = conf_slow_timestamp
    }
    else
    {
        count = machine_slow_count
        time = machine_slow_time
        ip = machine_slow_ip
        status = machine_slow_status
        method = machine_slow_method
        url = machine_slow_url
        host = machine_slow_host
        timestamp = machine_slow_timestamp
    }

    #
    # Create indexes.
    #
    delete slow_order

    for (i = 1; i <= count; i++)
        slow_order[i] = time[i]

    #
    # Sort descending.
    #
    for (i = 1; i <= count; i++)
    {
        for (j = i + 1; j <= count; j++)
        {
            if (slow_order[j] > slow_order[i])
            {
                tmp = slow_order[i]
                slow_order[i] = slow_order[j]
                slow_order[j] = tmp
            }
        }
    }

    limit = count

    if (limit > TOP)
        limit = TOP

    print "    \"slowest_requests\": ["

    first = 1

    delete slow_used

    for (i = 1; i <= limit; i++)
    {
        target_time = slow_order[i]

        for (j = 1; j <= count; j++)
        {
            if (!slow_used[j] && time[j] == target_time)
            {
                if (!first)
                    print ","

                printf "      {\"time_s\":%.3f,\"ip\":\"%s\",\"status\":%d,\"method\":\"%s\",\"url\":\"%s\",\"host\":\"%s\",\"timestamp\":\"%s\"}",
                       time[j],
                       json_escape(ip[j]),
                       status[j],
                       json_escape(method[j]),
                       json_escape(url[j]),
                       json_escape(host[j]),
                       json_escape(timestamp[j])

                slow_used[j] = 1
                first = 0

                break
            }
        }
    }

    print ""
    print "    ],"
}


###############################################################################
# PRINT ATTACKS
###############################################################################

function print_attacks(prefix)
{
    if (prefix == "conf")
    {
        hits = conf_attack_hits
        example = conf_attack_example
        ip = conf_attack_ip
        timestamp = conf_attack_timestamp
    }
    else
    {
        hits = machine_attack_hits
        example = machine_attack_example
        ip = machine_attack_ip
        timestamp = machine_attack_timestamp
    }

    delete attack_order

    n = 0

    for (key in hits)
        attack_order[++n] = key

    #
    # Sort by hits.
    #
    for (i = 1; i <= n; i++)
    {
        for (j = i + 1; j <= n; j++)
        {
            if (hits[attack_order[j]] >
                hits[attack_order[i]])
            {
                tmp = attack_order[i]
                attack_order[i] = attack_order[j]
                attack_order[j] = tmp
            }
        }
    }

    print "    \"attacks\": ["

    for (i = 1; i <= n; i++)
    {
        key = attack_order[i]

        if (i > 1)
            print ","

        printf "      {\"indicator\":\"%s\",\"hits\":%d,\"example\":\"%s\",\"ip\":\"%s\",\"timestamp\":\"%s\"}",
               json_escape(key),
               hits[key],
               json_escape(example[key]),
               json_escape(ip[key]),
               json_escape(timestamp[key])
    }

    print ""
    print "    ]"
}


###############################################################################
# PRINT CONFIGURATION AGGREGATE
###############################################################################

function print_configuration_aggregate()
{
    print "      \"requests\": {"

    printf "        \"total\":%d,\n",
           conf_total["requests"]

    printf "        \"errors\":%d,\n",
           conf_total["errors"]

    printf "        \"bytes\":%d,\n",
           conf_total["bytes"]

    printf "        \"search requests\":%d\n",
           conf_total["search_requests"]

    print "      },"

    print "      \"latency\": {"

    printf "        \"total_us\":%d,\n",
           conf_latency["total_us"]

    if (conf_total["requests"] > 0)
    {
        printf "        \"avg_ms\":%.3f,\n",
               conf_latency["total_us"] /
               conf_total["requests"] / 1000

        printf "        \"min_ms\":%.3f,\n",
               conf_latency["min_us"] / 1000

        printf "        \"max_ms\":%.3f\n",
               conf_latency["max_us"] / 1000
    }
    else
    {
        print "        \"avg_ms\":0,"
        print "        \"min_ms\":0,"
        print "        \"max_ms\":0"
    }

    print "      },"

    print "      \"security\": {"

    printf "        \"bot_requests\":%d,\n",
           conf_security["bot_requests"]

    printf "        \"human_requests\":%d,\n",
           conf_security["human_requests"]

    printf "        \"automatic_requests\":%d\n",
           conf_security["automatic_requests"]

    print "      },"

    #
    # Rankings
    #
    print "      \"rankings\": {"

    print "        \"limit\":50,"

    printf "        \"ips\":"
    print_ranking(conf_rank, "ip", conf_total["requests"])
    print ","

    printf "        \"status\":"
    print_ranking(conf_rank, "status", conf_total["requests"])
    print ","

    printf "        \"hosts\":"
    print_ranking(conf_rank, "host", conf_total["requests"])
    print ","

    printf "        \"urls\":"
    print_ranking(conf_rank, "url", conf_total["requests"])
    print ","

    printf "        \"search\":"
    print_ranking(conf_rank, "search", conf_total["search_requests"])
    print ","

    printf "        \"user_agents\":"
    print_ranking(conf_rank, "user_agent", conf_total["requests"])
    print ","

    printf "        \"methods\":"
    print_ranking(conf_rank, "method", conf_total["requests"])
    print ","

    printf "        \"referers\":"
    print_ranking(conf_rank, "referer", conf_total["requests"])
    print ","

    printf "        \"extensions\":"
    print_ranking(conf_rank, "extension", conf_total["requests"])
    print ","

    printf "        \"bots\":"
    print_ranking(conf_rank, "bot", conf_total["requests"])
    print ","

    printf "        \"automation\":"
    print_ranking(conf_rank, "automation", conf_total["requests"])

    print "      },"

    #
    # Slowest requests
    #
    print_slowest("conf")

    #
    # Attacks
    #
    print_attacks("conf")
}


###############################################################################
# PRINT MACHINE AGGREGATE
###############################################################################

function print_machine_aggregate()
{
    print "  \"requests\": {"

    printf "    \"total\":%d,\n",
           machine_total["requests"]

    printf "    \"errors\":%d,\n",
           machine_total["errors"]

    printf "    \"bytes\":%d,\n",
           machine_total["bytes"]

    printf "    \"search requests\":%d\n",
           machine_total["search_requests"]

    print "  },"

    print "  \"latency\": {"

    printf "    \"total_us\":%d,\n",
           machine_latency["total_us"]

    if (machine_total["requests"] > 0)
    {
        printf "    \"avg_ms\":%.3f,\n",
               machine_latency["total_us"] /
               machine_total["requests"] / 1000

        printf "    \"min_ms\":%.3f,\n",
               machine_latency["min_us"] / 1000

        printf "    \"max_ms\":%.3f\n",
               machine_latency["max_us"] / 1000
    }
    else
    {
        print "    \"avg_ms\":0,"
        print "    \"min_ms\":0,"
        print "    \"max_ms\":0"
    }

    print "  },"

    print "  \"security\": {"

    printf "    \"bot_requests\":%d,\n",
           machine_security["bot_requests"]

    printf "    \"human_requests\":%d,\n",
           machine_security["human_requests"]

    printf "    \"automatic_requests\":%d\n",
           machine_security["automatic_requests"]

    print "  },"

    #
    # Rankings
    #
    print "  \"rankings\": {"

    print "    \"limit\":50,"

    printf "    \"ips\":"
    print_ranking(machine_rank, "ip", machine_total["requests"])
    print ","

    printf "    \"status\":"
    print_ranking(machine_rank, "status", machine_total["requests"])
    print ","

    printf "    \"hosts\":"
    print_ranking(machine_rank, "host", machine_total["requests"])
    print ","

    printf "    \"urls\":"
    print_ranking(machine_rank, "url", machine_total["requests"])
    print ","

    printf "    \"search\":"
    print_ranking(machine_rank, "search", machine_total["search_requests"])
    print ","

    printf "    \"user_agents\":"
    print_ranking(machine_rank, "user_agent", machine_total["requests"])
    print ","

    printf "    \"methods\":"
    print_ranking(machine_rank, "method", machine_total["requests"])
    print ","

    printf "    \"referers\":"
    print_ranking(machine_rank, "referer", machine_total["requests"])
    print ","

    printf "    \"extensions\":"
    print_ranking(machine_rank, "extension", machine_total["requests"])
    print ","

    printf "    \"bots\":"
    print_ranking(machine_rank, "bot", machine_total["requests"])
    print ","

    printf "    \"automation\":"
    print_ranking(machine_rank, "automation", machine_total["requests"])

    print "  },"

    #
    # Slowest
    #
    print_slowest("machine")

    #
    # Attacks
    #
    print_attacks("machine")
}


###############################################################################
# MAIN
###############################################################################

{
    JSON_FILE = FILENAME

    ###########################################################################
    # Extract configuration and domain from:
    #
    # /tmp/access-audit/conf_r01/sede/access-audit-2026-08-19.json
    #
    ###########################################################################

    path = JSON_FILE

    sub(/^.*\/access-audit-[0-9]{4}-[0-9]{2}-[0-9]{2}\.json$/, "", path)

    #
    # Get domain.
    #
    tmp = JSON_FILE

    sub(/^.*\//, "", tmp)
    sub(/^access-audit-[0-9]{4}-[0-9]{2}-[0-9]{2}\.json$/, "", tmp)

    #
    # Remove trailing slash.
    #
    domain = tmp

    #
    # Configuration = directory immediately before domain.
    #
    tmp = JSON_FILE
    sub(/\/[^/]+\/access-audit-[0-9]{4}-[0-9]{2}-[0-9]{2}\.json$/, "", tmp)
    sub(/^.*\//, "", tmp)

    configuration = tmp


    ###########################################################################
    # Configuration change
    ###########################################################################

    if (current_configuration != configuration)
    {
        #
        # Finish previous configuration.
        #
        if (current_configuration != "")
        {
            print "      ],"

            print_configuration_aggregate()

            print "    }"
            print "  ],"
        }

        #
        # Start new configuration.
        #
        current_configuration = configuration

        reset_configuration()

        #
        # Configuration header.
        #
        print "    {"

        printf "      \"configuration\":\"%s\",\n",
               json_escape(configuration)

        print "      \"domains\": ["

        first_domain = 1
    }


    ###########################################################################
    # Domain separator
    ###########################################################################

    if (!first_domain)
        print ","

    first_domain = 0


    ###########################################################################
    # Corresponding aggregate file
    ###########################################################################

    AGG_FILE = JSON_FILE

    sub(/\.json$/, ".agg", AGG_FILE)


    ###########################################################################
    # Read aggregate
    ###########################################################################

    process_aggregate(AGG_FILE)


    ###########################################################################
    # Read complete domain JSON
    ###########################################################################

    DOMAIN_JSON = read_file(JSON_FILE)


    ###########################################################################
    # Domain
    ###########################################################################

    print "        {"

    printf "          \"domain\":\"%s\",\n",
           json_escape(domain)

    printf "          \"audit\":%s",
           DOMAIN_JSON

    print ""
    print "        }"
}


###############################################################################
# END
###############################################################################

END
{
    ###########################################################################
    # Close last configuration
    ###########################################################################

    if (current_configuration != "")
    {
        print "      ],"

        print_configuration_aggregate()

        print "    }"
        print "  ],"
    }


    ###########################################################################
    # Machine aggregate
    ###########################################################################

    print "  \"date\":\"" json_escape(DATE) "\","
    print "  \"machine\":\"" json_escape(MACHINE) "\","
    print "  \"source\":\"" json_escape(SOURCE) "\","

    print_machine_aggregate()

    #
    # print_machine_aggregate() leaves the attacks array as the last member,
    # so we only need to close the root object.
    #
    print "}"
}
