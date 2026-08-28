###############################################################################
#
# Access Audit - Machine Collector
#
###############################################################################
#
# Inputs:
#
#   access-audit-YYYY-MM-DD.agg
#   access-audit-YYYY-MM-DD.json
#
# The .agg files are the source for machine/configuration aggregation.
# The .json files are kept as the detailed domain audit.
#
###############################################################################


###############################################################################
# CONFIGURATION
###############################################################################
BEGIN
{
    first_config = 1
    first_domain = 1

    n_uniq_files = split(UNIQ_FILES, uniq_files, "\n")

    for (i = 1; i <= n_uniq_files; i++)
    {
        if (uniq_files[i] != "")
            process_unique(uniq_files[i])
    }
}



FILENAME ~ /\.agg$/ {
    process_aggregate(FILENAME)
    next
}

FILENAME ~ /\.json$/ {
    process_json(FILENAME)
    next
}

FILENAME ~ /\.uniq\.gz$/ {
    process_unique(FILENAME)
    next
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

    sub(/\n$/, "", content)

    return content
}


###############################################################################
# PATH INFORMATION
###############################################################################

function get_path_info(filename, parts,    n, i)
{
    n = split(filename, parts, "/")

    config = ""
    domain = ""

    for (i = 1; i <= n; i++)
    {
        if (parts[i] ~ /^conf/)
        {
            config = parts[i]

            if (i < n)
                domain = parts[i + 1]
        }
    }

    return config SUBSEP domain
}


###############################################################################
# INITIALISE CONFIGURATION
###############################################################################

function init_config(config)
{
    if (!(config in config_seen))
    {
        config_seen[config] = 1

        config_requests[config] = 0
        config_errors[config] = 0
        config_bytes[config] = 0
        config_search_requests[config] = 0

        config_latency_total[config] = 0
        config_latency_min[config] = 0
        config_latency_max[config] = 0

        config_bot_requests[config] = 0
        config_human_requests[config] = 0
        config_automatic_requests[config] = 0
    }
}


###############################################################################
# INITIALISE RANKING
###############################################################################

function add_ranking(type, value, hits, config)
{
    if (value == "")
        return

    machine_rank[type SUBSEP value] += hits
    config_rank[config SUBSEP type SUBSEP value] += hits
}


###############################################################################
# ADD SLOW REQUEST
###############################################################################

function add_slow(config, time_s, ip, status, method, url, host, timestamp,    n)
{
    n = ++machine_slow_count

    machine_slow_time[n] = time_s
    machine_slow_ip[n] = ip
    machine_slow_status[n] = status
    machine_slow_method[n] = method
    machine_slow_url[n] = url
    machine_slow_host[n] = host
    machine_slow_timestamp[n] = timestamp

    n = ++config_slow_count[config]

    config_slow_time[config SUBSEP n] = time_s
    config_slow_ip[config SUBSEP n] = ip
    config_slow_status[config SUBSEP n] = status
    config_slow_method[config SUBSEP n] = method
    config_slow_url[config SUBSEP n] = url
    config_slow_host[config SUBSEP n] = host
    config_slow_timestamp[config SUBSEP n] = timestamp
}


###############################################################################
# ADD ATTACK
###############################################################################

function add_attack(config, indicator, hits, example, ip, timestamp)
{
    if (indicator == "")
        return

    machine_attack_hits[indicator] += hits

    if (!(indicator in machine_attack_example) ||
        hits > machine_attack_example_hits[indicator])
    {
        machine_attack_example_hits[indicator] = hits
        machine_attack_example[indicator] = example
        machine_attack_ip[indicator] = ip
        machine_attack_timestamp[indicator] = timestamp
    }

    config_attack_hits[config SUBSEP indicator] += hits

    if (!(config SUBSEP indicator in config_attack_example) ||
        hits > config_attack_example_hits[config SUBSEP indicator])
    {
        config_attack_example_hits[config SUBSEP indicator] = hits
        config_attack_example[config SUBSEP indicator] = example
        config_attack_ip[config SUBSEP indicator] = ip
        config_attack_timestamp[config SUBSEP indicator] = timestamp
    }
}


###############################################################################
# PROCESS AGGREGATE
###############################################################################

function process_aggregate(filename,    line, f, n, type, config, value, hits)
{
    config = ""

    while ((getline line < filename) > 0)
    {
        if (line == "")
            continue

        n = split(line, f, "|")

        type = f[1]

        #######################################################################
        # METADATA
        #######################################################################

        if (type == "configuration")
        {
            config = f[2]
            init_config(config)
            continue
        }

        if (type == "title")
            continue

        if (type == "date")
            continue


        #######################################################################
        # TOTALS
        #######################################################################

        if (type == "total")
        {
            value = f[3] + 0

            if (f[2] == "requests")
            {
                machine_requests += value
                machine_total_requests += value
                config_requests[config] += value
            }
            else if (f[2] == "errors")
            {
                machine_errors += value
                config_errors[config] += value
            }
            else if (f[2] == "bytes")
            {
                machine_bytes += value
                config_bytes[config] += value
            }
            else if (f[2] == "search_requests")
            {
                machine_search_requests += value
                config_search_requests[config] += value
            }

            continue
        }


        #######################################################################
        # LATENCY
        #######################################################################

        if (type == "latency")
        {
            value = f[3] + 0

            if (f[2] == "total_us")
            {
                machine_latency_total += value
                config_latency_total[config] += value
            }
            else if (f[2] == "min_us")
            {
                if (config_latency_min[config] == 0 ||
                    value < config_latency_min[config])
                    config_latency_min[config] = value

                if (machine_latency_min == 0 ||
                    value < machine_latency_min)
                    machine_latency_min = value
            }
            else if (f[2] == "max_us")
            {
                if (value > config_latency_max[config])
                    config_latency_max[config] = value

                if (value > machine_latency_max)
                    machine_latency_max = value
            }

            continue
        }


        #######################################################################
        # SECURITY
        #######################################################################

        if (type == "security")
        {
            value = f[3] + 0

            if (f[2] == "bot_requests")
            {
                machine_bot_requests += value
                config_bot_requests[config] += value
            }
            else if (f[2] == "human_requests")
            {
                machine_human_requests += value
                config_human_requests[config] += value
            }
            else if (f[2] == "automatic_requests")
            {
                machine_automatic_requests += value
                config_automatic_requests[config] += value
            }

            continue
        }


        #######################################################################
        # UNIQUE
        #
        # Deliberately ignored.
        #
        # Unique counters cannot be summed between domains because the same
        # IP, URL, host, etc. may appear in several domains.
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

            add_ranking(type, value, hits, config)

            continue
        }


        #######################################################################
        # SLOWEST REQUEST
        #######################################################################

        if (type == "slow")
        {
	    add_slow(config, f[2] + 0, f[3], f[4] + 0, f[5], f[6], f[7], f[8])
            continue
        }


        #######################################################################
        # ATTACK
        #######################################################################

        if (type == "attack")
        {
            add_attack(config, f[2], f[3] + 0, f[4], f[5], f[6])
            continue
        }
    }

    close(filename)
}


###############################################################################
# PROCESS JSON
###############################################################################

function process_json(filename,    info, parts, config, domain, content)
{
    info = get_path_info(filename, parts)

    split(info, path_info, SUBSEP)

    config = path_info[1]
    domain = path_info[2]

    if (config == "")
        config = "unknown"

    if (domain == "")
        domain = "unknown"

    init_config(config)

    content = read_file(filename)

    domain_json[config SUBSEP domain] = content
    domain_seen[config SUBSEP domain] = 1

    domain_config[domain] = config
}


################################################################################
## PROCESS UNIQUE
################################################################################

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

        if (value == "")
            continue

        machine_unique[type SUBSEP value] = 1
    }
	
    close(cmd)
        print "DEBUG UNIQUE END" > "/dev/stderr"
}


###############################################################################
# PROCESS UNIQUE
###############################################################################

#function process_unique(filename,    cmd, line, f, type, value,
#                        total, urls, methods, empty)
#{
#    cmd = "gzip -cd " filename

#    total = 0
#    urls = 0
#    methods = 0
#    empty = 0

#    while ((cmd | getline line) > 0)
#    {
#        total++

#        if (line == "")
#            continue

#        split(line, f, "|")

#        type = f[1]
#        value = f[2]

#        if (type == "url")
#            urls++

#        if (type == "method")
#            methods++

#        if (value == "")
#        {
#            empty++
#            continue
#        }

#        machine_unique[type SUBSEP value] = 1
#    }

#    close(cmd)

#    printf "DEBUG UNIQUE [%s]: total=%d urls=%d methods=%d empty=%d\n",
#           filename, total, urls, methods, empty > "/dev/stderr"
#}

###############################################################################
# COUNT UNIQUE
###############################################################################
function count_machine_unique(type,    key, prefix, count)
{
    prefix = type SUBSEP
    count = 0

    for (key in machine_unique)
    {
        if (index(key, prefix) == 1)
            count++
    }

    return count
}

###############################################################################
# COLLECT RANKING
###############################################################################
function collect_machine_ranking(type, values, hits,
                                  key, value, n)
{
    delete values
    delete hits

    n = 0

    for (key in machine_rank)
    {
        if (index(key, type SUBSEP) == 1)
        {
            value = substr(key, length(type) + 2)

            values[++n] = value
            hits[value] = machine_rank[key]
        }
    }

    return n
}


###############################################################################
# COLLECT CONFIGURATION RANKING
###############################################################################

function collect_config_ranking(config, type, values, hits,
                                key, value, prefix, n)
{
    delete values
    delete hits

    n = 0
    prefix = config SUBSEP type SUBSEP

    for (key in config_rank)
    {
        if (index(key, prefix) == 1)
        {
            value = substr(key, length(prefix) + 1)

            values[++n] = value
            hits[value] = config_rank[key]
        }
    }

    return n
}


###############################################################################
# PRINT RANKING
###############################################################################

function print_ranking(values, hits, n, total,
                       indent, percent_total,
                       sorted, i, limit, value)
{
    asorti(hits, sorted, "@val_num_desc")

    limit = n

    if (limit > TOP)
        limit = TOP

    print "["

    for (i = 1; i <= limit; i++)
    {
        value = sorted[i]

        if (i > 1)
            print ","

        if (percent_total > 0)
            pct = (hits[value] / percent_total) * 100
        else
            pct = 0

        printf "%s{\"value\":\"%s\",\"hits\":%d,\"percent\":%.3f}",
               indent,
               json_escape(value),
               hits[value],
               pct 
    }

    print ""
    printf "%s]", indent
}


###############################################################################
# PRINT MACHINE RANKINGS
###############################################################################

function print_machine_rankings()
{
    print "  \"rankings\": {"
    print "    \"limit\":50,"

    n = collect_machine_ranking("ip", values, hits)
    printf "    \"ips\":"
    print_ranking(values, hits, n, machine_requests, "    ", machine_requests)
    print ","

    n = collect_machine_ranking("status", values, hits)
    printf "    \"status\":"
    print_ranking(values, hits, n, machine_requests, "    ", machine_requests)
    print ","

    n = collect_machine_ranking("host", values, hits)
    printf "    \"hosts\":"
    print_ranking(values, hits, n, machine_requests, "    ", machine_requests)
    print ","

    n = collect_machine_ranking("url", values, hits)
    printf "    \"urls\":"
    print_ranking(values, hits, n, machine_requests, "    ", machine_requests)
    print ","

    n = collect_machine_ranking("search", values, hits)
    printf "    \"search\":"
    print_ranking(values, hits, n, machine_search_requests, "    ", machine_search_requests)
    print ","

    n = collect_machine_ranking("user_agent", values, hits)
    printf "    \"user_agents\":"
    print_ranking(values, hits, n, machine_requests, "    ", machine_requests)
    print ","

    n = collect_machine_ranking("method", values, hits)
    printf "    \"methods\":"
    print_ranking(values, hits, n, machine_requests, "    ", machine_requests)
    print ","

    n = collect_machine_ranking("referer", values, hits)
    printf "    \"referers\":"
    print_ranking(values, hits, n, machine_requests, "    ", machine_requests)
    print ","

    n = collect_machine_ranking("extension", values, hits)
    printf "    \"extensions\":"
    print_ranking(values, hits, n, machine_requests, "    ", machine_requests)
    print ","

    n = collect_machine_ranking("bot", values, hits)
    printf "    \"bots\":"
    print_ranking(values, hits, n, machine_requests, "    ", machine_requests)
    print ","

    n = collect_machine_ranking("automation", values, hits)
    printf "    \"automation\":"
    print_ranking(values, hits, n, machine_requests, "    ", machine_requests)

    print ""
    print "  },"
}


###############################################################################
# PRINT CONFIGURATION RANKINGS
###############################################################################

function print_config_rankings(config)
{
    print "    \"rankings\": {"
    print "      \"limit\":50,"

    n = collect_config_ranking(config, "ip", values, hits)
    printf "      \"ips\":"
    print_ranking(values, hits, n, config_requests[config], "      ", config_requests[config])
    print ","

    n = collect_config_ranking(config, "status", values, hits)
    printf "      \"status\":"
    print_ranking(values, hits, n, config_requests[config], "      ", config_requests[config])
    print ","

    n = collect_config_ranking(config, "host", values, hits)
    printf "      \"hosts\":"
    print_ranking(values, hits, n, config_requests[config], "      ", config_requests[config])
    print ","

    n = collect_config_ranking(config, "url", values, hits)
    printf "      \"urls\":"
    print_ranking(values, hits, n, config_requests[config], "      ", config_requests[config])
    print ","

    n = collect_config_ranking(config, "search", values, hits)
    printf "      \"search\":"
    print_ranking(values, hits, n, config_search_requests[config], "      ", config_search_requests[config])
    print ","

    n = collect_config_ranking(config, "user_agent", values, hits)
    printf "      \"user_agents\":"
    print_ranking(values, hits, n, config_requests[config], "      ", config_requests[config])
    print ","

    n = collect_config_ranking(config, "method", values, hits)
    printf "      \"methods\":"
    print_ranking(values, hits, n, config_requests[config], "      ", config_requests[config])
    print ","

    n = collect_config_ranking(config, "referer", values, hits)
    printf "      \"referers\":"
    print_ranking(values, hits, n, config_requests[config], "      ", config_requests[config])
    print ","

    n = collect_config_ranking(config, "extension", values, hits)
    printf "      \"extensions\":"
    print_ranking(values, hits, n, config_requests[config], "      ", config_requests[config])
    print ","

    n = collect_config_ranking(config, "bot", values, hits)
    printf "      \"bots\":"
    print_ranking(values, hits, n, config_requests[config], "      ", config_requests[config])
    print ","

    n = collect_config_ranking(config, "automation", values, hits)
    printf "      \"automation\":"
    print_ranking(values, hits, n, config_requests[config], "      ", config_requests[config])

    print ""
    print "    },"
}


###############################################################################
# PRINT TOTALS
###############################################################################

function print_requests(requests, errors, bytes, searches, indent)
{
    printf "%s\"requests\": {\n", indent
    printf "%s  \"total\":%d,\n", indent, requests
    printf "%s  \"errors\":%d,\n", indent, errors
    printf "%s  \"bytes\":%d,\n", indent, bytes
    printf "%s  \"search requests\":%d\n", indent, searches
    printf "%s}", indent
}


###############################################################################
# PRINT LATENCY
###############################################################################

function print_latency(total, min, max, requests, indent)
{
    printf "%s\"latency\": {\n", indent
    printf "%s  \"total_us\":%d,\n", indent, total

    if (requests > 0)
    {
        printf "%s  \"avg_ms\":%.3f,\n",
               indent,
               total / requests / 1000

        printf "%s  \"min_ms\":%.3f,\n",
               indent,
               min / 1000

        printf "%s  \"max_ms\":%.3f\n",
               indent,
               max / 1000
    }
    else
    {
        printf "%s  \"avg_ms\":0,\n", indent
        printf "%s  \"min_ms\":0,\n", indent
        printf "%s  \"max_ms\":0\n", indent
    }

    printf "%s}", indent
}


###############################################################################
# PRINT SECURITY
###############################################################################

function print_security(bot, human, automatic, indent)
{
    printf "%s\"security\": {\n", indent
    printf "%s  \"bot_requests\":%d,\n", indent, bot
    printf "%s  \"human_requests\":%d,\n", indent, human
    printf "%s  \"automatic_requests\":%d\n", indent, automatic
    printf "%s}", indent
}


###############################################################################
# PRINT SLOWEST
###############################################################################

function print_slowest_machine()
{
    print "  \"slowest_requests\": ["

    delete slow_index

    for (i = 1; i <= machine_slow_count; i++)
        slow_index[i] = machine_slow_time[i]

    asorti(slow_index, sorted, "@val_num_desc")

    limit = machine_slow_count

    if (limit > TOP)
        limit = TOP

    for (i = 1; i <= limit; i++)
    {
        n = sorted[i]

        if (i > 1)
            print ","

        printf "    {\"time_s\":%.3f,\"ip\":\"%s\",\"status\":%d,\"method\":\"%s\",\"url\":\"%s\",\"host\":\"%s\",\"timestamp\":\"%s\"}",
               machine_slow_time[n],
               json_escape(machine_slow_ip[n]),
               machine_slow_status[n],
               json_escape(machine_slow_method[n]),
               json_escape(machine_slow_url[n]),
               json_escape(machine_slow_host[n]),
               json_escape(machine_slow_timestamp[n])
    }

    print ""
    print "  ],"
}


###############################################################################
# PRINT CONFIGURATION SLOWEST
###############################################################################

function print_config_slowest(config,    prefix, i, n, count, order, limit)
{
    count = config_slow_count[config]

    printf "      \"slowest_requests\": ["

    if (count == 0)
    {
        print "],"
        return
    }

    delete order

    for (i = 1; i <= count; i++)
        order[i] = config_slow_time[config SUBSEP i]

    asorti(order, sorted, "@val_num_desc")

    limit = count

    if (limit > TOP)
        limit = TOP

    for (i = 1; i <= limit; i++)
    {
        n = sorted[i]

        if (i > 1)
            print ","

        printf "        {\"time_s\":%.3f,\"ip\":\"%s\",\"status\":%d,\"method\":\"%s\",\"url\":\"%s\",\"host\":\"%s\",\"timestamp\":\"%s\"}",
               config_slow_time[config SUBSEP n],
               json_escape(config_slow_ip[config SUBSEP n]),
               config_slow_status[config SUBSEP n],
               json_escape(config_slow_method[config SUBSEP n]),
               json_escape(config_slow_url[config SUBSEP n]),
               json_escape(config_slow_host[config SUBSEP n]),
               json_escape(config_slow_timestamp[config SUBSEP n])
    }

    print ""
    print "      ],"
}


###############################################################################
# PRINT ATTACKS - MACHINE
###############################################################################

function print_machine_attacks(    n, i, key, sorted, indicator)
{
    n = asorti(machine_attack_hits, sorted, "@val_num_desc")

    print "  \"attacks\": ["

    for (i = 1; i <= n; i++)
    {
        indicator = sorted[i]

        if (i > 1)
            print ","

        printf "    {\"indicator\":\"%s\",\"hits\":%d,\"example\":\"%s\",\"ip\":\"%s\",\"timestamp\":\"%s\"}",
               json_escape(indicator),
               machine_attack_hits[indicator],
               json_escape(machine_attack_example[indicator]),
               json_escape(machine_attack_ip[indicator]),
               json_escape(machine_attack_timestamp[indicator])
    }

    print ""
    print "  ],"
}


###############################################################################
# PRINT ATTACKS - CONFIGURATION
###############################################################################

function print_config_attacks(config,    prefix, n, i, key, sorted, indicator)
{
    prefix = config SUBSEP

    delete attack_values

    n = 0

    for (key in config_attack_hits)
    {
        if (index(key, prefix) == 1)
        {
            indicator = substr(key, length(prefix) + 1)

            attack_values[indicator] = config_attack_hits[key]
        }
    }

    n = asorti(attack_values, sorted, "@val_num_desc")

    print "      \"attacks\": ["

    for (i = 1; i <= n; i++)
    {
        indicator = sorted[i]

        if (i > 1)
            print ","

        printf "        {\"indicator\":\"%s\",\"hits\":%d,\"example\":\"%s\",\"ip\":\"%s\",\"timestamp\":\"%s\"}",
               json_escape(indicator),
               attack_values[indicator],
               json_escape(config_attack_example[prefix indicator]),
               json_escape(config_attack_ip[prefix indicator]),
               json_escape(config_attack_timestamp[prefix indicator])
    }

    print ""
    print "      ],"
}


###############################################################################
# PRINT DOMAINS
###############################################################################

function print_domains(config,    key, domain, prefix, n, sorted, i)
{
    prefix = config SUBSEP

    delete domains

    n = 0

    for (key in domain_seen)
    {
        if (index(key, prefix) == 1)
        {
            domain = substr(key, length(prefix) + 1)
            domains[++n] = domain
        }
    }

    asort(domains)

    print "      \"domains\": ["

    for (i = 1; i <= n; i++)
    {
        domain = domains[i]

        if (i > 1)
            print ","

        printf "        {\"domain\":\"%s\",\"audit\":%s}",
               json_escape(domain),
               domain_json[config SUBSEP domain]
    }

    print ""
    print "      ]"
}


###############################################################################
# PRINT CONFIGURATION
###############################################################################

function print_configuration(config)
{
    print "    {"

    printf "      \"configuration\":\"%s\",\n",
           json_escape(config)

    print "      \"audit\": {"

    print_requests(config_requests[config], config_errors[config], config_bytes[config], config_search_requests[config], "        ")

    print ","

    print_latency(config_latency_total[config],config_latency_min[config],config_latency_max[config],config_requests[config],"        ")

    print ","

    print_security(config_bot_requests[config],config_human_requests[config],config_automatic_requests[config],"        ")

    print ","

    # Rankings
    print_config_rankings(config)

    # slowest_requests
    print_config_slowest(config)

    # attacks
    print_config_attacks(config)

    # domains
    print_domains(config)

    print "      }"
    print "    }"
}


###############################################################################
# PRINT MACHINE RANKING
###############################################################################

function print_machine_ranking_report(type, title, total,
                                      key, value, n, sorted, i, limit)
{
    delete ranking_values

    n = 0

    for (key in machine_rank)
    {
        if (index(key, type SUBSEP) == 1)
        {
            value = substr(key, length(type) + 2)
            ranking_values[value] = machine_rank[key]
        }
    }

    n = asorti(ranking_values, sorted, "@val_num_desc")

    print ""
    print title
    print ""

    if (n == 0)
    {
        print "No data"
        return
    }

    limit = n

    if (limit > TOP)
        limit = TOP

    printf "%-5s %-12s %-10s %s\n",
           "#",
           "Peticiones",
           "%",
           "Valor"

    print "-----------------------------------------------------------------------"

    for (i = 1; i <= limit; i++)
    {
        value = sorted[i]

        if (total > 0)
            pct = (ranking_values[value] / total) * 100
        else
            pct = 0

        printf "%-5d %-12d %-9.2f %s\n",
               i,
               ranking_values[value],
               pct,
               value
    }
}





###############################################################################
# END
###############################################################################

END {

print "DEBUG BEFORE UNIQUE COUNTS" > "/dev/stderr"

    machine_unique_ips        = count_machine_unique("ip")
    machine_unique_hosts      = count_machine_unique("host")
    machine_unique_urls       = count_machine_unique("url")
    machine_unique_useragents = count_machine_unique("user_agent")
    machine_unique_methods    = count_machine_unique("method")
    machine_unique_referers   = count_machine_unique("referer")
    machine_unique_extensions = count_machine_unique("extension")

print "DEBUG AFTER UNIQUE COUNTS" > "/dev/stderr"

    ###########################################################################
    # MACHINE JSON
    ###########################################################################

    print "{"

    printf "  \"date\":\"%s\",\n",
           json_escape(DATE)

    printf "  \"source\":\"%s\",\n",
           json_escape(SOURCE)

    printf "  \"machine\":\"%s\",\n",
           json_escape(MACHINE)

    print "  \"requests\": {"

    printf "    \"total\":%d,\n",
           machine_requests

    printf "    \"errors\":%d,\n",
           machine_errors

    printf "    \"bytes\":%d,\n",
           machine_bytes

    printf "    \"search requests\":%d\n",
           machine_search_requests

    print "  },"

    print "  \"latency\": {"

    printf "    \"total_us\":%d,\n",
           machine_latency_total

    if (machine_requests > 0)
    {
        printf "    \"avg_ms\":%.3f,\n",
               machine_latency_total / machine_requests / 1000

        printf "    \"min_ms\":%.3f,\n",
               machine_latency_min / 1000

        printf "    \"max_ms\":%.3f\n",
               machine_latency_max / 1000
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
           machine_bot_requests

    printf "    \"human_requests\":%d,\n",
           machine_human_requests

    printf "    \"automatic_requests\":%d\n",
           machine_automatic_requests

    print "  },"

    ###########################################################################
    # UNIQUEs
    ###########################################################################
    print "  \"unique\": {"
    printf "    \"ips\":%d,\n", machine_unique_ips
    printf "    \"hosts\":%d,\n", machine_unique_hosts
    printf "    \"urls\":%d,\n", machine_unique_urls
    printf "    \"user_agents\":%d,\n", machine_unique_useragents
    printf "    \"methods\":%d,\n", machine_unique_methods
    printf "    \"referers\":%d,\n", machine_unique_referers
    printf "    \"extensions\":%d\n", machine_unique_extensions
    print "  },"

    ###########################################################################
    # MACHINE RANKINGS
    ###########################################################################

    print_machine_rankings()

    ###########################################################################
    # MACHINE SLOWEST
    ###########################################################################

    print_slowest_machine()

    ###########################################################################
    # MACHINE ATTACKS
    ###########################################################################

    print_machine_attacks()

    ###########################################################################
    # CONFIGURATIONS
    ###########################################################################

    print "  \"configurations\": ["

    delete configs
    n_configs = 0

    for (config in config_seen)
        configs[++n_configs] = config

    asort(configs)

    for (i = 1; i <= n_configs; i++)
    {
        if (i > 1)
            print ","

        print_configuration(configs[i])
    }

    print ""
    print "  ]"

    print "}"

    ###########################################################################
    # HUMAN READABLE REPORT
    ###########################################################################

    print_machine_console_report()
}

###############################################################################
# PRINT MACHINE REPORT
###############################################################################

function print_machine_console_report()
{
    print "" > "/dev/stderr"
    print "" > "/dev/stderr"
    print "=======================================================================" > "/dev/stderr"
    print "                     Machine access audit" > "/dev/stderr"
    print "=======================================================================" > "/dev/stderr"

    printf "%-24s : %s\n", "Machine", MACHINE > "/dev/stderr"
    printf "%-24s : %s\n", "Date", DATE > "/dev/stderr"

    print "" > "/dev/stderr"
    print "• REQUESTS •" > "/dev/stderr"
    print "" > "/dev/stderr"

    printf "%-24s : %d\n", "Peticiones", machine_requests > "/dev/stderr"
    printf "%-24s : %d\n", "Búsquedas", machine_search_requests > "/dev/stderr"
    printf "%-24s : %s\n", "Bytes enviados", format_bytes(machine_bytes) > "/dev/stderr"
    printf "%-24s : %d\n", "IPs únicas", machine_unique_ips > "/dev/stderr"
    printf "%-24s : %d\n", "Hosts", machine_unique_hosts > "/dev/stderr"
    printf "%-24s : %d\n", "URLs", machine_unique_urls > "/dev/stderr"
    printf "%-24s : %d\n", "User-Agent", machine_unique_useragents > "/dev/stderr"
    printf "%-24s : %d\n", "Methods", machine_unique_methods > "/dev/stderr"
    printf "%-24s : %d\n", "Referers", machine_unique_referers > "/dev/stderr"
    printf "%-24s : %d\n", "Extensions", machine_unique_extensions > "/dev/stderr"
    printf "%-24s : %d\n", "Errores HTTP", machine_errors > "/dev/stderr"

    print "" > "/dev/stderr"
    print "• LATENCY •" > "/dev/stderr"
    print "" > "/dev/stderr"

    if (machine_requests > 0)
    {
        printf "%-24s : %.3f ms\n",
               "Media",
               machine_latency_total / machine_requests / 1000 > "/dev/stderr"

        printf "%-24s : %.3f ms\n",
               "Mínima",
               machine_latency_min / 1000 > "/dev/stderr"

        printf "%-24s : %.3f ms\n",
               "Máxima",
               machine_latency_max / 1000 > "/dev/stderr"
    }

    print "" > "/dev/stderr"
    print "• SECURITY •" > "/dev/stderr"
    print "" > "/dev/stderr"

    printf "%-24s : %d\n", "Bot requests", machine_bot_requests > "/dev/stderr"
    printf "%-24s : %d\n", "Human requests", machine_human_requests > "/dev/stderr"
    printf "%-24s : %d\n", "Automatic requests", machine_automatic_requests > "/dev/stderr"

    print "" > "/dev/stderr"
    print "=======================================================================" > "/dev/stderr"
}
