###############################################################################
#
# Access Audit - Machine Collector
#
###############################################################################

BEGIN {

    first_configuration = 1
    first_domain = 1
    current_configuration = ""

    print "{"
    print "  \"configurations\": ["
}


###############################################################################
# PROCESS JSON FILE
###############################################################################

{
    file = FILENAME

    #
    # Extract configuration and domain from path
    #
    configuration = ""
    domain = ""

    n = split(file, path, "/")

    for (i = 1; i <= n; i++) {

        if (path[i] ~ /^conf_[^/]+$/) {

            configuration = path[i]

            if ((i + 1) <= n)
                domain = path[i + 1]

            break
        }
    }


    #
    # Ignore files whose path cannot be identified
    #
    if (configuration == "" || domain == "")
        next


    ###########################################################################
    # NEW CONFIGURATION
    ###########################################################################

    if (configuration != current_configuration) {

        #
        # Close previous configuration
        #
        if (!first_configuration) {

            print ""
            print "      ]"
            print "    },"
        }


        #
        # Start configuration
        #
        print "    {"
        print "      \"configuration\": \"" configuration "\","
        print "      \"domains\": ["

        current_configuration = configuration

        first_configuration = 0
        first_domain = 1
    }


    ###########################################################################
    # DOMAIN
    ###########################################################################

    if (!first_domain)
        print ","

    print "        {"
    print "          \"domain\": \"" domain "\","
    print "          \"audit\": "


    ###########################################################################
    # COPY ORIGINAL JSON
    ###########################################################################

    while ((getline line < file) > 0) {

        sub(/\r$/, "", line)

        print line
    }

    close(file)


    print ""
    print "        }"

    first_domain = 0
}


###############################################################################
# END
###############################################################################

END {

    if (!first_configuration) {

        print ""
        print "      ]"
        print "    }"
    }

    print ""
    print "  ]"
    print "}"
}
