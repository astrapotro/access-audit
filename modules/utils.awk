###############################################################################
# Devuelve un número con separador de miles.
# Compatible con GNU Awk 4.0
###############################################################################

function format_number(value,      s,len,res,i,c)
{
    value=int(value)
    s=sprintf("%d",value)

    len=length(s)
    res=""
    c=0

    for(i=len;i>=1;i--)
    {
        res=substr(s,i,1) res
        c++

        if(c==3 && i>1)
        {
            res="." res
            c=0
        }
    }

    return res
}

###############################################################################
# Repite un carácter N veces
###############################################################################

function repeat(c, n,    s, i)
{
    s = ""

    for (i = 1; i <= n; i++)
        s = s c

    return s
}

###############################################################################
# Devuelve un porcentaje.
###############################################################################

function format_percent(value,total)
{
    if(total==0)
        return "0.00"

    return sprintf("%.2f",(value*100)/total)
}

###############################################################################
# Convierte bytes a formato legible.
###############################################################################

function format_bytes(bytes)
{
    if(bytes>1099511627776)
        return sprintf("%.2f TB",bytes/1099511627776)

    if(bytes>1073741824)
        return sprintf("%.2f GB",bytes/1073741824)

    if(bytes>1048576)
        return sprintf("%.2f MB",bytes/1048576)

    if(bytes>1024)
        return sprintf("%.2f KB",bytes/1024)

    return bytes " B"
}

###############################################################################
# Convierte microsegundos.
###############################################################################

function format_time(us)
{
    if(us>1000000)
        return sprintf("%.2f s",us/1000000)

    if(us>1000)
        return sprintf("%.2f ms",us/1000)

    return us " us"
}

###############################################################################
# Formatea porcentaje sobre el total de peticiones
###############################################################################

function percent(value)
{
    if (stat_requests == 0)
        return "0.00"

    return sprintf("%.2f", (value * 100) / stat_requests)
}



###############################################################################
# UTILS
###############################################################################

function trim(str)
{
    gsub(/^[ \t]+/,"",str)
    gsub(/[ \t]+$/,"",str)

    return str
}


###############################################################################
# Devuelve la extensión de una URL.
###############################################################################

function get_extension(url,      n,a,file)
{
    split(url,a,"/")

    file=a[length(a)]

    n=split(file,a,".")

    if(n<2)
        return ""

    return tolower(a[n])
}

###############################################################################
# Devuelve 1 si es un recurso estático.
###############################################################################

function is_static_resource(ext)
{
    return ( ext=="css"  ||
             ext=="js"   ||
             ext=="gif"  ||
             ext=="jpg"  ||
             ext=="jpeg" ||
             ext=="png"  ||
             ext=="svg"  ||
             ext=="ico"  ||
             ext=="woff" ||
             ext=="woff2"||
             ext=="ttf"  ||
             ext=="map"  ||
             ext=="webp")
}


###############################################################################
# Elimina la zona horaria del timestamp
###############################################################################

function format_timestamp(ts)
{
    sub(/ [+-][0-9]{4}$/, "", ts)
    return ts
}


###############################################################################
# Comprueba si un array tiene datos
###############################################################################
   
function array_has_data(arr,    key)
{

    for (key in arr)
    {
        if (arr[key] > 0)
            return 1
	
    }

    return 0
}
