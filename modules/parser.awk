###############################################################################
# RECORD
###############################################################################
#
# Variables correspondientes al registro actualmente procesado.
#
###############################################################################

function clear_record()
{
##    rec_client=""
    rec_balancer=""
    rec_timestamp=""

    rec_method=""
    rec_url=""
    rec_query=""
    rec_protocol=""

    rec_status=0
    rec_size=0
    rec_time=0

    rec_host=""
    rec_useragent=""
    rec_referer=""
    rec_accept=""
    rec_ip=""
}


###############################################################################
# Analiza la petición HTTP.
###############################################################################

function parse_request(request,    n, a, p)
{
    rec_method=""
    rec_url=""
    rec_query=""
    rec_protocol=""

    n = split(request, a, " ")

    if (n >= 1)
        rec_method = a[1]

    if (n >= 2)
    {
        p = index(a[2], "?")

        if (p > 0)
        {
            rec_url   = substr(a[2], 1, p - 1)
            rec_query = substr(a[2], p + 1)
        }
        else
        {
            rec_url = a[2]
        }
    }

    if (n >= 3)
        rec_protocol = a[3]
}

###############################################################################
# Analiza una línea completa del log.
###############################################################################

function parse_line(    request)
{
    clear_record()

##    rec_client    = extract_tag($0, "Client:")
    rec_balancer  = extract_tag($0, "Balancer IP:")
#    rec_status    = extract_tag($0, "Response:")
    rec_status    = extract_tag($0, "Response:") + 0
#    rec_size      = extract_tag($0, "Size:")
    rec_size      = extract_tag($0, "Size:") + 0
#    rec_time      = extract_tag($0, "Time(us):")
    rec_time = extract_tag($0, "Time(us):") + 0

    rec_host      = extract_quoted($0, "Host:\"")
    rec_useragent = extract_quoted($0, "User-Agent:\"")
    rec_accept    = extract_quoted($0, "Accept:\"")
    rec_referer   = extract_quoted($0, "Referer:\"")
    rec_ip 	  = extract_tag($0, "Client:")

##	if (NR <= 3)
##	{
##	    print "LINE=[" $0 "]"
##	    print "IP EXTRACT=[" rec_ip "]"
##	}    

    request = extract_request($0)

    parse_request(request)

    if (match($0, /\[[^]]+\]/))
    {
        rec_timestamp = substr($0, RSTART + 1, RLENGTH - 2)
    }

    register_slow_request()
}

###############################################################################
# Devuelve el contenido situado detrás de una etiqueta.
###############################################################################

function extract_tag(line, tag,    p, s)
{
    p = index(line, tag)

    if (p == 0)
        return ""

    s = substr(line, p + length(tag))

    sub(/^ +/, "", s)

    if (match(s, /^[^ ]+/))
        return substr(s, RSTART, RLENGTH)

    return ""
}

###############################################################################
# Devuelve el contenido de:
#
# Host:"xxxxx"
#
###############################################################################

function extract_quoted(line, tag,    p, s, q)
{
    p = index(line, tag)

    if (p == 0)
        return ""

    s = substr(line, p + length(tag))

    q = index(s, "\"")

    if (q == 0)
        return ""

    return substr(s, 1, q - 1)
}


###############################################################################
# Extrae la petición HTTP del log.
#
# Busca:
#
#   "GET /... HTTP/1.1"
#
# evitando depender del orden de los campos entrecomillados.
###############################################################################

function extract_request(line,    p1,p2,s)
{
    p1 = index(line, "\"")

    while (p1 > 0)
    {
        s = substr(line, p1 + 1)

        p2 = index(s, "\"")

        if (p2 == 0)
	{
##    	    print "METHOD NOT FOUND: " line 
            return ""
	}

        s = substr(s, 1, p2 - 1)

        if (s ~ /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)[ ]/)
            return s

        p1 += p2
        p1 += index(substr(line, p1 + 1), "\"")
    }

    return ""
}
