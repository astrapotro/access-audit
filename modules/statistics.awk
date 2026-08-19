###############################################################################
# Actualiza todas las estadísticas del registro actual.
###############################################################################

function update_statistics()
{
    stat_requests++

    stat_total_bytes += rec_size
    stat_total_time  += rec_time



    # Primera petición: inicializamos mínimo y máximo
    if (stat_requests == 1)
    {
        stat_min_time = rec_time
        stat_max_time = rec_time
    }
    else
    {
        if (rec_time < stat_min_time)
            stat_min_time = rec_time

        if (rec_time > stat_max_time)
            stat_max_time = rec_time
    }

    update_ip()
    update_host()
    update_url()
    update_status()
    update_useragent()
    update_method()
    update_referer()
    update_extension()
    update_search()
}

function update_ip()
{
    if (stat_requests <= 5)
    {
##        print "DEBUG IP=[" rec_ip "]"
    }

    if (!(rec_ip in stat_ip))
        stat_unique_ips++

    stat_ip[rec_ip]++
}

function update_host()
{
    if (!(rec_host in stat_host))
        stat_unique_hosts++

    stat_host[rec_host]++
}

function update_url()
{
    if (!(rec_url in stat_url))
        stat_unique_urls++

    stat_url[rec_url]++
}


function update_status()
{
    stat_status[rec_status]++

    if (rec_status >= 400)
        stat_errors++
}

function update_useragent()
{
    if (!(rec_useragent in stat_useragent))
        stat_unique_useragents++

    stat_useragent[rec_useragent]++
}


function update_method()
{
    if (!(rec_method in stat_method))
        stat_unique_methods++

    stat_method[rec_method]++
}


function update_referer()
{

   if (rec_referer == "")
        return

    if (!(rec_referer in stat_referer))
        stat_unique_referers++

    stat_referer[rec_referer]++
}


function update_extension(    extension, path)
{
    path = rec_url

    if (path ~ /\.[^\/.]+$/)
    {
        extension = path
        sub(/^.*\./, "", extension)
        extension = tolower(extension)
    }
    else
    {
        extension = "[none]"
    }

    if (!(extension in stat_extension))
        stat_unique_extensions++

    stat_extension[extension]++
}



function update_search()
{
 if (!detect_search(rec_query))
        return

    stat_search_requests++

    register_search(rec_url "?" rec_query)

}


