function update_security(    bot, automation)
{
    bot = detect_bot(rec_useragent)

    if (bot != "")
    {
        stat_bot_requests++
        stat_bot[bot]++
        return
    }

    automation = detect_automation(rec_useragent)

    if (automation != "")
    {
        stat_aut_requests++
        stat_automation[automation]++
        return
    }

    stat_human_requests++
}


function update_attacks()
{
    detect_sqli()
    detect_traversal()
    detect_lfi()
    detect_rfi()
    detect_sensitive_files()
    detect_command_injection()
    detect_scanners()
}

###############################################################################
# Registra un ataque detectado
###############################################################################

function register_attack(name)
{
    stat_attack[name]++

    if (!(name in attack_example))
    {
        attack_example[name]   = rec_method " " rec_url
        attack_ip[name]        = rec_ip
        attack_timestamp[name] = rec_timestamp
    }
}

###############################################################################
# Detecta bots conocidos
###############################################################################

function detect_bot(ua, l)
{
    l = tolower(ua)

    if (l ~ /googlebot/)             return "Googlebot"
    if (l ~ /bingbot/)               return "Bingbot"
    if (l ~ /claudebot/)             return "ClaudeBot"
    if (l ~ /gptbot/)                return "GPTBot"
    if (l ~ /chatgpt-user/)          return "ChatGPT-User"
    if (l ~ /facebookexternalhit/)   return "Facebook"
    if (l ~ /slurp/)                 return "Yahoo"
    if (l ~ /duckduckbot/)           return "DuckDuckBot"
    if (l ~ /yandex/)                return "Yandex"
    if (l ~ /baiduspider/)           return "Baidu"
    if (l ~ /applebot/)              return "Applebot"

    return ""
}

###############################################################################
# Detecta clientes de automatización
###############################################################################

function detect_automation(ua, l)
{
    l = tolower(ua)

    # Headless browsers
    if (l ~ /headlesschrome/)       return "HeadlessChrome"
    if (l ~ /playwright/)           return "Playwright"
    if (l ~ /puppeteer/)            return "Puppeteer"
    if (l ~ /selenium/)             return "Selenium"
    if (l ~ /phantomjs/)            return "PhantomJS"
    if (l ~ /cypress/)              return "Cypress"

    # CLI
    if (l ~ /curl\//)               return "curl"
    if (l ~ /wget\//)               return "wget"
    if (l ~ /httpie/)               return "HTTPie"

    # HTTP libraries
    if (l ~ /python-requests/)      return "python-requests"
    if (l ~ /aiohttp/)              return "aiohttp"
    if (l ~ /urllib/)               return "urllib"
    if (l ~ /go-http-client/)       return "Go-http-client"
    if (l ~ /okhttp/)               return "OkHttp"
    if (l ~ /apache-httpclient/)    return "Apache HttpClient"
    if (l ~ /libwww-perl/)          return "libwww-perl"

    # Java
    if (l ~ /java\//)               return "Java"

    # API testing
    if (l ~ /postmanruntime/)       return "Postman"
    if (l ~ /insomnia/)             return "Insomnia"

    # Load testing
    if (l ~ /apachebench/)          return "ApacheBench"
    if (l ~ / jmeter/)              return "JMeter"
    if (l ~ /k6/)                   return "k6"
    if (l ~ /gatling/)              return "Gatling"

    return ""
}

######################################################################################
# Funciones de detección de ataques
######################################################################################
function detect_sqli(    url)
{
    url = tolower(rec_url)

    if (url ~ /union[[:space:]]+select/)
        register_attack("SQL Injection")

    if (url ~ /information_schema/)
        register_attack("SQL Injection")

    if (url ~ /sleep\(/)
        register_attack("SQL Injection")

    if (url ~ /benchmark\(/)
        register_attack("SQL Injection")

    if (url ~ /load_file\(/)
        register_attack("SQL Injection")

    if (url ~ /into[[:space:]]+outfile/)
        register_attack("SQL Injection")
}

function detect_traversal(    url)
{
    url = tolower(rec_url)

    if (url ~ /\.\.\//)
        register_attack("Path Traversal")

    if (url ~ /%2e%2e/)
        register_attack("Path Traversal")

    if (url ~ /%252e%252e/)
        register_attack("Path Traversal")
}

function detect_sensitive_files(    url)
{
    url = tolower(rec_url)

    if (url ~ /\/etc\/passwd/)
        register_attack("/etc/passwd")

    if (url ~ /boot\.ini/)
        register_attack("boot.ini")

    if (url ~ /win\.ini/)
        register_attack("win.ini")

    if (url ~ /\.env/)
        register_attack(".env")

    if (url ~ /id_rsa/)
        register_attack("SSH Private Key")
}

function detect_scanners(    url)
{
    url = tolower(rec_url)

    if (url ~ /wp-login\.php/)
        register_attack("WordPress Scan")

    if (url ~ /xmlrpc\.php/)
        register_attack("WordPress Scan")

    if (url ~ /manager\/html/)
        register_attack("Tomcat Scan")

    if (url ~ /actuator/)
        register_attack("Spring Boot Scan")

    if (url ~ /phpmyadmin/)
        register_attack("phpMyAdmin Scan")
}

###############################################################################
# Local File Inclusion (LFI)
###############################################################################

function detect_lfi()
{
}

###############################################################################
# Remote File Inclusion (RFI)
###############################################################################

function detect_rfi()
{
}

###############################################################################
# Command Injection
###############################################################################

function detect_command_injection()
{
}
