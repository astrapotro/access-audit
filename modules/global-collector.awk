###############################################################################
#
# Access Audit - Global Collector
#
###############################################################################

###############################################################################
# CONFIGURATION
###############################################################################

BEGIN {
    DEFAULT_TOP = 50

    machine_count = 0

    n_json = split(MACHINE_JSON_FILES, json_files, "\n")
    n_uniq = split(MACHINE_UNIQ_FILES, uniq_files, "\n")

    for (i = 1; i <= n_uniq; i++)
    {
        if (uniq_files[i] != "")
            process_unique(uniq_files[i])
    }

    for (i = 1; i <= n_json; i++)
    {
        if (json_files[i] != "")
        {
            machine_count++
            process_machine_json(json_files[i])
        }
    }

    if (machine_count != EXPECTED_MACHINES)
    {
        print "ERROR: expected " EXPECTED_MACHINES \
              " machines, processed " machine_count > "/dev/stderr"

        exit 1
    }
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
# JSON STRING EXTRACTION
#
# Extracts a JSON string value from one line.
#
# Example:
#
#   "value":"hello"
#
###############################################################################

function json_string(line, key,    p, start, i, c, result, escaped)
{
    p = index(line, "\"" key "\":\"")

    if (p == 0)
        return ""

    start = p + length(key) + 4

    result = ""
    escaped = 0

    for (i = start; i <= length(line); i++)
    {
        c = substr(line, i, 1)

        if (escaped)
        {
            if (c == "n")
                result = result "\n"
            else if (c == "r")
                result = result "\r"
            else if (c == "t")
                result = result "\t"
            else if (c == "\"")
                result = result "\""
            else if (c == "\\")
                result = result "\\"
            else if (c == "/")
                result = result "/"
            else
                result = result c

            escaped = 0
            continue
        }

        if (c == "\\")
        {
            escaped = 1
            continue
        }

        if (c == "\"")
            break

        result = result c
    }

    return result
}


###############################################################################
# JSON NUMBER EXTRACTION
###############################################################################

function json_number(line, key,    p, start, rest, value)
{
    p = index(line, "\"" key "\":")

    if (p == 0)
        return ""

    start = p + length(key) + 3
    rest = substr(line, start)

    match(rest, /^-?[0-9]+(\.[0-9]+)?/)

    if (RLENGTH == 0)
        return ""

    value = substr(rest, RSTART, RLENGTH)

    return value + 0
}


###############################################################################
# PROCESS UNIQUE
###############################################################################

function process_unique(filename,    cmd, line, f, type, value)
{
    cmd = "gzip -cd " filename

    while ((cmd | getline line) > 0)
    {
        if (line == "")
            continue

        split(line, f, "|")

        type = f[1]
        value = f[2]

        if (type == "" || value == "")
            continue

        global_unique[type SUBSEP value] = 1
    }

    close(cmd)
}


###############################################################################
# COUNT UNIQUE
###############################################################################

function count_unique(type,    key, prefix, count)
{
    prefix = type SUBSEP
    count = 0

    for (key in global_unique)
    {
        if (index(key, prefix) == 1)
            count++
    }

    return count
}


###############################################################################
# PROCESS MACHINE JSON
###############################################################################

function process_machine_json(filename,    line, section, value, hits, type)
{
    section = ""

    while ((getline line < filename) > 0)
    {
        #######################################################################
        # REQUESTS
        #######################################################################

        if (line ~ /"requests": *\{/)
        {
            section = "requests"
            continue
        }

        if (section == "requests")
        {
            if (line ~ /"total":/)
                global_requests += json_number(line, "total")

            else if (line ~ /"errors":/)
                global_errors += json_number(line, "errors")

            else if (line ~ /"bytes":/)
                global_bytes += json_number(line, "bytes")

            else if (line ~ /"search requests":/)
                global_search_requests += json_number(line, "search requests")

            if (line ~ /^[[:space:]]*}/)
                section = ""

            continue
        }

        #######################################################################
        # LATENCY
        #######################################################################

        if (line ~ /"latency": *\{/)
        {
            section = "latency"
            continue
        }

        if (section == "latency")
        {
            if (line ~ /"total_us":/)
                global_latency_total += json_number(line, "total_us")

            else if (line ~ /"min_ms":/)
            {
                value = json_number(line, "min_ms")

                if (global_latency_min == 0 || value < global_latency_min)
                    global_latency_min = value
            }

            else if (line ~ /"max_ms":/)
            {
                value = json_number(line, "max_ms")

                if (value > global_latency_max)
                    global_latency_max = value
            }

            if (line ~ /^[[:space:]]*}/)
                section = ""

            continue
        }

        #######################################################################
        # SECURITY
        #######################################################################

        if (line ~ /"security": *\{/)
        {
            section = "security"
            continue
        }

        if (section == "security")
        {
            if (line ~ /"bot_requests":/)
                global_bot_requests += json_number(line, "bot_requests")

            else if (line ~ /"human_requests":/)
                global_human_requests += json_number(line, "human_requests")

            else if (line ~ /"automatic_requests":/)
                global_automatic_requests += json_number(line, "automatic_requests")

            if (line ~ /^[[:space:]]*}/)
                section = ""

            continue
        }

        #######################################################################
        # RANKINGS
        #######################################################################

        if (line ~ /"ips": *\[/)
        {
            ranking_section = "ip"
            continue
        }

        if (line ~ /"status": *\[/)
        {
            ranking_section = "status"
            continue
        }

        if (line ~ /"hosts": *\[/)
        {
            ranking_section = "host"
            continue
        }

        if (line ~ /"urls": *\[/)
        {
            ranking_section = "url"
            continue
        }

        if (line ~ /"search": *\[/)
        {
            ranking_section = "search"
            continue
        }

        if (line ~ /"user_agents": *\[/)
        {
            ranking_section = "user_agent"
            continue
        }

        if (line ~ /"methods": *\[/)
        {
            ranking_section = "method"
            continue
        }

        if (line ~ /"referers": *\[/)
        {
            ranking_section = "referer"
            continue
        }

        if (line ~ /"extensions": *\[/)
        {
            ranking_section = "extension"
            continue
        }

        if (line ~ /"bots": *\[/)
        {
            ranking_section = "bot"
            continue
        }

        if (line ~ /"automation": *\[/)
        {
            ranking_section = "automation"
            continue
        }

        if (ranking_section != "")
        {
            if (line ~ /"value":/)
            {
                value = json_string(line, "value")
                hits = json_number(line, "hits")

                if (value != "")
                    global_rank[ranking_section SUBSEP value] += hits
            }

            if (line ~ /^[[:space:]]*\]/)
                ranking_section = ""

            continue
        }

        #######################################################################
        # SLOWEST REQUESTS
        #######################################################################

        if (line ~ /"slowest_requests": *\[/)
        {
            slow_section = 1
            continue
        }

        if (slow_section)
        {
            if (line ~ /"time_s":/)
            {
                n = ++global_slow_count

                global_slow_time[n] = json_number(line, "time_s")
                global_slow_ip[n] = json_string(line, "ip")
                global_slow_status[n] = json_number(line, "status")
                global_slow_method[n] = json_string(line, "method")
                global_slow_url[n] = json_string(line, "url")
                global_slow_host[n] = json_string(line, "host")
                global_slow_timestamp[n] = json_string(line, "timestamp")
            }

            if (line ~ /^[[:space:]]*\]/)
                slow_section = 0

            continue
        }

        #######################################################################
        # ATTACKS
        #######################################################################

        if (line ~ /"attacks": *\[/)
        {
            attack_section = 1
            continue
        }

        if (attack_section)
        {
            if (line ~ /"indicator":/)
            {
                type = json_string(line, "indicator")
                hits = json_number(line, "hits")

                if (type != "")
                {
                    global_attack_hits[type] += hits

                    if (!(type in global_attack_example) ||
                        hits > global_attack_example_hits[type])
                    {
                        global_attack_example_hits[type] = hits
                        global_attack_example[type] = json_string(line, "example")
                        global_attack_ip[type] = json_string(line, "ip")
                        global_attack_timestamp[type] = json_string(line, "timestamp")
                    }
                }
            }

            if (line ~ /^[[:space:]]*\]/)
                attack_section = 0

            continue
        }
    }

    close(filename)
}


###############################################################################
# SORT / PRINT RANKING
###############################################################################

function print_ranking(type, total,    values, key, value, n, sorted, i, limit, pct)
{
    delete values

    n = 0

    for (key in global_rank)
    {
        if (index(key, type SUBSEP) == 1)
        {
            value = substr(key, length(type) + 2)
            values[value] = global_rank[key]
        }
    }

    n = asorti(values, sorted, "@val_num_desc")

    limit = n

    if (limit > DEFAULT_TOP)
        limit = DEFAULT_TOP

    print "["

    for (i = 1; i <= limit; i++)
    {
        value = sorted[i]

        if (i > 1)
            print ","

        if (total > 0)
            pct = (values[value] / total) * 100
        else
            pct = 0

        printf "      {\"value\":\"%s\",\"hits\":%d,\"percent\":%.3f}",
               json_escape(value),
               values[value],
               pct
    }

    print ""
    print "    ]"
}


###############################################################################
# PRINT SLOWEST REQUESTS
###############################################################################

function print_slowest(    sorted, i, n, limit)
{
    delete slow_index

    for (i = 1; i <= global_slow_count; i++)
        slow_index[i] = global_slow_time[i]

    n = asorti(slow_index, sorted, "@val_num_desc")

    limit = n

    if (limit > DEFAULT_TOP)
        limit = DEFAULT_TOP

    print "  \"slowest_requests\": ["

    for (i = 1; i <= limit; i++)
    {
        n = sorted[i]

        if (i > 1)
            print ","

        printf "    {\"time_s\":%.3f,\"ip\":\"%s\",\"status\":%d,\"method\":\"%s\",\"url\":\"%s\",\"host\":\"%s\",\"timestamp\":\"%s\"}",
               global_slow_time[n],
               json_escape(global_slow_ip[n]),
               global_slow_status[n],
               json_escape(global_slow_method[n]),
               json_escape(global_slow_url[n]),
               json_escape(global_slow_host[n]),
               json_escape(global_slow_timestamp[n])
    }

    print ""
    print "  ],"
}


###############################################################################
# PRINT ATTACKS
###############################################################################

function print_attacks(    sorted, n, i, indicator)
{
    n = asorti(global_attack_hits, sorted, "@val_num_desc")

    print "  \"attacks\": ["

    for (i = 1; i <= n; i++)
    {
        indicator = sorted[i]

        if (i > 1)
            print ","

        printf "    {\"indicator\":\"%s\",\"hits\":%d,\"example\":\"%s\",\"ip\":\"%s\",\"timestamp\":\"%s\"}",
               json_escape(indicator),
               global_attack_hits[indicator],
               json_escape(global_attack_example[indicator]),
               json_escape(global_attack_ip[indicator]),
               json_escape(global_attack_timestamp[indicator])
    }

    print ""
    print "  ]"
}


###############################################################################
# PRINT GLOBAL JSON
###############################################################################

END {

    ###########################################################################
    # UNIQUE COUNTS
    ###########################################################################

    global_unique_ips        = count_unique("ip")
    global_unique_hosts      = count_unique("host")
    global_unique_urls       = count_unique("url")
    global_unique_useragents = count_unique("user_agent")
    global_unique_methods    = count_unique("method")
    global_unique_referers   = count_unique("referer")
    global_unique_extensions = count_unique("extension")

    ###########################################################################
    # JSON
    ###########################################################################

    print "{"

    printf "  \"date\":\"%s\",\n",
           json_escape(DATE)

    printf "  \"source\":\"%s\",\n",
           json_escape(SOURCE)

    printf "  \"machines\":%d,\n",
           machine_count

    ###########################################################################
    # REQUESTS
    ###########################################################################

    print "  \"requests\": {"

    printf "    \"total\":%d,\n",
           global_requests

    printf "    \"errors\":%d,\n",
           global_errors

    printf "    \"bytes\":%d,\n",
           global_bytes

    printf "    \"search requests\":%d\n",
           global_search_requests

    print "  },"

    ###########################################################################
    # LATENCY
    ###########################################################################

    print "  \"latency\": {"

    printf "    \"total_us\":%d,\n",
           global_latency_total

    if (global_requests > 0)
    {
        printf "    \"avg_ms\":%.3f,\n",
               global_latency_total / global_requests / 1000

        printf "    \"min_ms\":%.3f,\n",
               global_latency_min

        printf "    \"max_ms\":%.3f\n",
               global_latency_max
    }
    else
    {
        print "    \"avg_ms\":0,"
        print "    \"min_ms\":0,"
        print "    \"max_ms\":0"
    }

    print "  },"

    ###########################################################################
    # SECURITY
    ###########################################################################

    print "  \"security\": {"

    printf "    \"bot_requests\":%d,\n",
           global_bot_requests

    printf "    \"human_requests\":%d,\n",
           global_human_requests

    printf "    \"automatic_requests\":%d\n",
           global_automatic_requests

    print "  },"

    ###########################################################################
    # UNIQUE
    ###########################################################################

    print "  \"unique\": {"

    printf "    \"ips\":%d,\n",
           global_unique_ips

    printf "    \"hosts\":%d,\n",
           global_unique_hosts

    printf "    \"urls\":%d,\n",
           global_unique_urls

    printf "    \"user_agents\":%d,\n",
           global_unique_useragents

    printf "    \"methods\":%d,\n",
           global_unique_methods

    printf "    \"referers\":%d,\n",
           global_unique_referers

    printf "    \"extensions\":%d\n",
           global_unique_extensions

    print "  },"

    ###########################################################################
    # RANKINGS
    ###########################################################################

    print "  \"rankings\": {"
    print "    \"limit\":50,"

    printf "    \"ips\":"
    print_ranking("ip", global_requests)
    print ","

    printf "    \"status\":"
    print_ranking("status", global_requests)
    print ","

    printf "    \"hosts\":"
    print_ranking("host", global_requests)
    print ","

    printf "    \"urls\":"
    print_ranking("url", global_requests)
    print ","

    printf "    \"search\":"
    print_ranking("search", global_search_requests)
    print ","

    printf "    \"user_agents\":"
    print_ranking("user_agent", global_requests)
    print ","

    printf "    \"methods\":"
    print_ranking("method", global_requests)
    print ","

    printf "    \"referers\":"
    print_ranking("referer", global_requests)
    print ","

    printf "    \"extensions\":"
    print_ranking("extension", global_requests)
    print ","

    printf "    \"bots\":"
    print_ranking("bot", global_requests)
    print ","

    printf "    \"automation\":"
    print_ranking("automation", global_requests)

    print "  },"

    ###########################################################################
    # SLOWEST
    ###########################################################################

    print_slowest()

    ###########################################################################
    # ATTACKS
    ###########################################################################

    print_attacks()

    print "}"
}
