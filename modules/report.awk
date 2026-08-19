function print_audit_header()
{
    print ""
    print ""
    print ""
    print "-----------------------------------------------------------------------"
    print " " AUDIT_FILE
    print " " AUDIT_CONFIGURATION
    print " " AUDIT_TITLE
    print " " AUDIT_DATE
    print "-----------------------------------------------------------------------"
}

function print_title(title)
{
    print ""
    print ""
    print "• "title" •"
    print ""
##    print repeat("-", length(title)+4)
}


function print_section(title)
{
    print ""
    print "-----------------------------------------------------------------------"
    print title
##    print repeat("-", length(title))
##    print ""
}


function print_http_summary()
{
    print_title("REQUESTS")

    printf("%-24s : %s\n", "Formato", FORMAT)
    printf("%-24s : %d\n", "Peticiones", stat_requests)
    printf("%-24s : %d (%.2f%%)\n", "Búsquedas", stat_search_requests, stat_requests ? (stat_search_requests / stat_requests) * 100 : 0)
    printf("%-24s : %s\n", "Bytes enviados", format_bytes(stat_total_bytes))
    printf("%-24s : %d\n", "IPs únicas", stat_unique_ips)
    printf("%-24s : %d\n", "Hosts", stat_unique_hosts)
    printf("%-24s : %d\n", "URLs", stat_unique_urls)
    printf("%-24s : %d\n", "User-Agent", stat_unique_useragents)
    printf("%-24s : %d\n", "Methods", stat_unique_methods)
    printf("%-24s : %d\n", "Referers", stat_unique_referers)
    printf("%-24s : %d\n", "Extensions", stat_unique_extensions)
    printf("%-24s : %d\n", "Errores HTTP", stat_errors)
}

function print_latency_summary()
{
    print_title("LATENCY")

    if (stat_requests == 0)
        return

    printf("%-24s : %.3f ms\n",
           "Media",
           stat_total_time / stat_requests / 1000)

    printf("%-24s : %.3f ms\n",
           "Mínima",
           stat_min_time / 1000)

    printf("%-24s : %.3f ms\n",
           "Máxima",
           stat_max_time / 1000)
}

function print_search_summary(    sorted, n, limit, i, url)
{
    print_title("SEARCH")

    printf("%-24s : %d\n",
           "Peticiones de búsqueda",
           stat_search_requests)

    printf("%-24s : %.2f%%\n",
           "Porcentaje",
           stat_requests ? (stat_search_requests / stat_requests) * 100 : 0)


    limit = DEFAULT_TOP 
    print ""
    print "Top " limit " search URLs"
    print ""

    n = sort_by_hits(search_urls, sorted)

    if (n == 0)
    {
        print "No search requests detected"
        return
    }

    if (limit > n)
        limit = n

    printf("%-5s %-12s %-10s %s\n",
           "#",
           "Peticiones",
           "%",
           "URL")

    print "-----------------------------------------------------------------------"

    for (i = 1; i <= limit; i++)
    {
        url = sorted[i]

        printf("%-5d %-12d %-9.2f %s\n",
               i,
               search_urls[url],
               (search_urls[url] / stat_search_requests) * 100,
               url)
    }
}

function print_security_summary()
{
    print_title("SECURITY")

    printf("%-24s : %d\n", "Bot requests", stat_bot_requests)

    printf("%-24s : %d\n", "Human requests", stat_human_requests)

    printf("%-24s : %d\n", "Automatic requests", stat_aut_requests)

    printf("%-24s : %d\n", "Headless requests", stat_headless_requests)
}

function print_attack_summary(    idx, attack, n, i)
{
    print_title("ATTACKS")

    n = 0

    for (attack in stat_attack)
    {
        n++

        printf("%-24s : %d\n",
               attack,
               stat_attack[attack])

        printf("  Example  : %s\n",
               attack_example[attack])

        printf("  IP       : %s\n",
               attack_ip[attack])

        printf("  Timestamp: %s\n",
               format_timestamp(attack_timestamp[attack]))

        print ""
    }

    if (n == 0)
        print "No attacks detected"
}


