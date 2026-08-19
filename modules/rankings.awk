###############################################################################
# RANKINGS
# Ordena un array por valor descendente.
# Devuelve un array con las claves ordenadas.
###############################################################################

function sort_by_hits(src, dst, key, n)
{
	return asorti(src, dst, "@val_num_desc")
}

###############################################################################
# Imprime un ranking genérico
###############################################################################
function report_ranking(array, title, limit,
                        sorted, n, i, key)
{
    print_section(title)

    n = sort_by_hits(array, sorted)

    if (limit > n)
        limit = n

    printf("%3s %10s %8s  %s\n",
           "#",
           "Hits",
           "%",
           "Value")

    print "-----------------------------------------------------------------------"

    for (i = 1; i <= limit; i++)
    {
        key = sorted[i]

	if (key == "")
	    continue

        printf("%3d %10d %7s%%  %s\n",
               i,
               array[key],
               percent(array[key]),
               key)
    }
}


function print_general_rankings()
{
    report_ranking(stat_ip,        "Top IPs",DEFAULT_TOP)
    report_ranking(stat_status,      "HTTP Status", DEFAULT_TOP)
    report_ranking(stat_host,      "Top Hosts",DEFAULT_TOP)
    report_ranking(stat_url,       "Top URLs",DEFAULT_TOP)
    report_ranking(stat_useragent, "Top User-Agent",DEFAULT_TOP)
    report_slowest_requests(DEFAULT_TOP)
}


###############################################################################
# Top peticiones por tiempo de respuesta
###############################################################################

function report_slowest_requests(limit,
                                 sorted, n, i, key)
{
    print_section("Slowest Requests")

    n = asorti(slow_time, sorted, "@val_num_desc")

    if (limit > n)
        limit = n

	printf("%3s %12s  %-15s %-6s %-7s %s\n",
       	"#",
       	"Time(s)",
       	"IP",
       	"Status",
       	"Method",
       	"URL")

	print "-----------------------------------------------------------------------"

	for (i = 1; i <= limit; i++)
	{
	    key = sorted[i]

	    printf("%3d %12.3f  %-15s %-6d %-7s %s\n",
	           i,
	           slow_time[key] / 1000000,
	           slow_ip[key],
	           slow_status[key],
	           slow_method[key],
	           slow_url[key])
	}

}



function print_security_rankings()
{
    if (array_has_data(stat_bot))
        report_ranking(stat_bot,
                       "Known Bots",
                       DEFAULT_TOP)

    if (array_has_data(stat_automation))
        report_ranking(stat_automation,
                       "Automation Clients",
                       DEFAULT_TOP)

    if (array_has_data(stat_attack))
        report_ranking(stat_attack,
                       "Attack Indicators",
                       DEFAULT_TOP)
}


###############################################################################
# Registra una petición para el ranking de latencia.
###############################################################################

function register_slow_request(    key)
{
    key = NR

    slow_time[key]       = rec_time
    slow_ip[key]         = rec_ip
    slow_status[key]     = rec_status
    slow_method[key]     = rec_method
    slow_url[key]        = rec_url
    slow_host[key]       = rec_host
    slow_useragent[key]  = rec_useragent
    slow_timestamp[key]  = rec_timestamp
}

