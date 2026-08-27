###############################################################################
# WRITE UNIQUE VALUES
###############################################################################

function write_unique()
{
    if (UNIQ_FILE == "")
        return

    write_unique_array("ip",          stat_ip)
    write_unique_array("host",        stat_host)
    write_unique_array("url",         stat_url)
    write_unique_array("user_agent",  stat_useragent)
    write_unique_array("method",      stat_method)
    write_unique_array("referer",     stat_referer)
    write_unique_array("extension",   stat_extension)

    close(UNIQ_FILE)
}


function write_unique_array(type, array,    key)
{
    for (key in array)
        print type "|" key > UNIQ_FILE
}
