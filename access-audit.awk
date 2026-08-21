###############################################################################
# MAIN
###############################################################################

{
    parse_line()

    update_statistics()

    update_security()

##    update_search() ---> in modules/statistics.awk
    
    update_attacks()

}

###############################################################################
# END
###############################################################################

END {

    print_audit_header()

    print_http_summary()

    print_general_rankings()

    print_search_summary()

    print_latency_summary()

    print_security_summary()

    print_security_rankings()

    print_attack_summary()

    print "DEBUG JSON_FILE=[" JSON_FILE "]" > "/dev/stderr"

    if (JSON_FILE != "")
    {
        print_json() > JSON_FILE
        close(JSON_FILE)
    }


}
