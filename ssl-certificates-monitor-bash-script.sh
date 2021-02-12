#!/usr/bin/env bash

### path, system and script variables declaration and initialization

declare -A serviceHostMapping
serviceHostMapping[sample.ssl.certificate.file.crt]="example.com"

# cleanup temp files if they exist
trap cleanup EXIT INT TERM QUIT

PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/ssl/bin:/usr/sfw/bin:/var/lib/jenkins/workspace/ssl-certificates-monitor/job_repo/
export PATH

# number of days in the warning threshhold (cmdline: -x)
warning_threshold=7

# null out the keystore_password variable for later use (cmdline: -k)
keystore_password=""

# type of certificate (cmdline: -t)
certificate_type="pem"

# system binaries
awk_cmd=$(command -v awk)
date_cmd=$(command -v date)
grep_cmd=$(command -v grep)
openssl_cmd=$(command -v openssl)
printf_cmd=$(command -v printf)
sed_cmd=$(command -v sed)
mktemp_cmd=$(command -v mktemp)
find_cmd=$(command -v find)
keytool_cmd=$(command -v keytool)
perl_cmd=$(command -v perl)
cut_cmd=$(command -v cut)

# set the default umask to be somewhat restrictive
umask 077

# start and end static values for the JSON Object
json_output_start='{"name":"sslCertificates","certificatesList":['
json_output_end=']}'

# variable to hold the entire JSON object, for output
json_output=''

### script functions

# remove temporary files if the script doesn't exit() cleanly
cleanup() {

    if [ -f "${certificate_temp_file}" ]; then
        rm -f "${certificate_temp_file}"
    fi

    if [ -f "${certificate_error_file}" ]; then
     rm -f "${certificate_error_file}"
    fi
}

# convert a date from MONTH-DAY-YEAR to Julian format
# arguments:
#   $1 -> Month (e.g., 06)
#   $2 -> Day   (e.g., 08)
#   $3 -> Year  (e.g., 2006)
date2julian() {

    if [ "${1}" != "" ] && [ "${2}" != "" ] && [ "${3}" != "" ]; then
        # Since leap years add aday at the end of February, calculations are done from 1 March 0000 (a fictional year)
        d2j_tmpmonth=$((12 * $3 + $1 - 3))

        # If it is not yet March, the year is changed to the previous year
        d2j_tmpyear=$(( d2j_tmpmonth / 12))

        # The number of days from 1 March 0000 is calculated and the number of days from 1 Jan. 4713BC is added
        echo $(( (734 * d2j_tmpmonth + 15) / 24
                 - 2 * d2j_tmpyear + d2j_tmpyear/4
                 - d2j_tmpyear/100 + d2j_tmpyear/400 + $2 + 1721119 ))
    else
        echo 0
    fi
}

# convert a string month into an integer representation
# arguments:
#   $1 -> Month name (e.g., Sep)
getmonth() {

    case ${1} in
        Jan) echo 1 ;;
        Feb) echo 2 ;;
        Mar) echo 3 ;;
        Apr) echo 4 ;;
        May) echo 5 ;;
        Jun) echo 6 ;;
        Jul) echo 7 ;;
        Aug) echo 8 ;;
        Sep) echo 9 ;;
        Oct) echo 10 ;;
        Nov) echo 11 ;;
        Dec) echo 12 ;;
          *) echo 0 ;;
    esac
}

# calculate the number of seconds between two dates
# arguments:
#   $1 -> Date #1
#   $2 -> Date #2
date_diff() {

    if [ "${1}" != "" ] && [ "${2}" != "" ]; then
        echo $((${2} - ${1}))
    else
        echo 0
    fi
}

# print a json object containing the SSL Certificates details and expiry date
# the command will only be invoked when for: -i -S -f arguments
# JSON Format Example:

# {
#  "name": "sslCertificates",
#  "certificatesList": [
#    {
#      "serialNumber": "03078B200F0XXXXXXXX42FBFA5E7C92F6C",
#      "ssl_certificate_common_name": "sample.net",
#      "issuer": "Let's Encrypt",
#      "hostName": "sample.net:443",
#      "status": "Valid",
#      "expiryDate": "Feb 20 2021",
#      "daysToExpire": "87"
#    }
#  ]
# }
prints_as_json() {

    output_file="${1}"

    if [ ! -f $output_file ]
    then
        touch $output_file
    else
        rm -fr $output_file
        touch $output_file
    fi

    echo "${json_output}" | jq '.' > $output_file
    cat $output_file
}

# connect to a server ($1) and port ($2) to see if a certificate has expired
# arguments:
#   $1 -> Server name
#   $2 -> TCP port to connect to
check_server_status() {

    port="$2"

    if [ "${tls_server_name}" = "FALSE" ]; then
        options="-connect ${1}:${2} $tls_flag"
    else
        options="-connect ${1}:${2} -servername ${1} $tls_flag"
    fi

    echo "" | "${openssl_cmd}" s_client $options 2> "${certificate_error_file}" 1> "${certificate_temp_file}"

    if "${grep_cmd}" -i "Connection refused" "${certificate_error_file}" > /dev/null; then
        echo "${1}" "${2}" "Connection refused" "Unknown"

    elif "${grep_cmd}" -i "No route to host" "${certificate_error_file}" > /dev/null; then
        echo "${1}" "${2}" "No route to host" "Unknown"

    elif "${grep_cmd}" -i "gethostbyname failure" "${certificate_error_file}" > /dev/null; then
        echo "${1}" "${2}" "Cannot resolve domain" "Unknown"

    elif "${grep_cmd}" -i "Operation timed out" "${certificate_error_file}" > /dev/null; then
        echo "${1}" "${2}" "Operation timed out" "Unknown"

    elif "${grep_cmd}" -i "ssl handshake failure" "${certificate_error_file}" > /dev/null; then
        echo "${1}" "${2}" "SSL handshake failed" "Unknown"

    elif "${grep_cmd}" -i "connect: Connection timed out" "${certificate_error_file}" > /dev/null; then
        echo "${1}" "${2}" "Connection timed out" "Unknown"

    elif "${grep_cmd}" -i "Name or service not known" "${certificate_error_file}" > /dev/null; then
        echo "${1}" "${2}" "Unable to resolve the DNS name ${1}" "Unknown"

    else
        check_file_status "${certificate_temp_file}" "${1}" "${2}"
    fi
}

# check the expiration status of a certificate file
# arguments:
#  $1 -> certificate file to process
#  $2 -> Server name
#  $3 -> port number of certificate
check_file_status() {

    certificate_file="${1}"
    host="${2}"
    port="${3}"

    # check to make sure the certificate file exists
    if [ ! -r "${certificate_file}" ] || [ ! -s "${certificate_file}" ]; then

        echo "ERROR: The file named ${certificate_file} is unreadable or doesn't exist"
        echo "ERROR: Please check to make sure the certificate for ${host}:${port} is valid"

        return
    fi

    # grab the expiration date from the X.509 certificate
    if [ "${keystore_password}" != "" ]; then

        # get the certificate from the PKCS#12 database, and send the informational message to /dev/null
        "${openssl_cmd}" pkcs12 -nokeys -in "${certificate_file}" -out "${certificate_temp_file}" -clcerts -password pass:"${keystore_password}" 2> /dev/null

        # get the expiration date from the certificate
        ssl_certificate_date=$("${openssl_cmd}" x509 -in "${certificate_temp_file}" -enddate -noout | "${sed_cmd}" 's/notAfter\=//')

        # get the issuer from the certificate
        ssl_certificate_issuer=$("${openssl_cmd}" x509 -in "${certificate_temp_file}" -issuer -noout | "${awk_cmd}" 'BEGIN {RS=", " } $0 ~ /^O =/ { print substr($0,5,21)}')

        # get the common name (CN) from the X.509 certificate
        ssl_certificate_common_name=$("${openssl_cmd}" x509 -in "${certificate_temp_file}" -subject -noout | "${sed_cmd}" -e 's/.*CN = //' | "${sed_cmd}" -e 's/, .*//')

        # get the serial number from the X.509 certificate
        ssl_certificate_serial_number=$("${openssl_cmd}" x509 -in "${certificate_temp_file}" -serial -noout | "${sed_cmd}" -e 's/serial=//')

    elif [ "${certificate_type}" == "crt" ]; then

        # get the expiration date from the ceriticate
        ssl_certificate_date=$("${keytool_cmd}" -printcert -v -file "${certificate_file}" | "${perl_cmd}" -ne 'if(/until: (.*?)\n/) { print "$1\n"; }')

        # get the issuer from the certificate
        ssl_certificate_issuer=$("${keytool_cmd}" -printcert -v -file "${certificate_file}" | "${perl_cmd}" -ne 'if(/Issuer: (.*?)\n/) { print "$1\n"; }' | "${cut_cmd}" -d ',' -f 1 | "${cut_cmd}" -c 4-)

        # get the common name (CN) from the X.509 certificate
        ssl_certificate_common_name=$("${keytool_cmd}" -printcert -v -file "${certificate_file}" | "${perl_cmd}" -ne 'if(/Owner: (.*?)\n/) { print "$1\n"; }' | "${cut_cmd}" -d ',' -f 1 | "${cut_cmd}" -c 4-)

        # get the serial number from the X.509 certificate
        ssl_certificate_serial_number=$("${keytool_cmd}" -printcert -v -file "${certificate_file}" | "${perl_cmd}" -ne 'if(/Serial number: (.*?)\n/) { print "$1\n"; }')

    else
        # get the expiration date from the ceriticate
        ssl_certificate_date=$("${openssl_cmd}" x509 -in "${certificate_file}" -enddate -noout -inform "${certificate_type}" | "${sed_cmd}" 's/notAfter\=//')

        # get the issuer from the certificate
        ssl_certificate_issuer=$("${openssl_cmd}" x509 -in "${certificate_file}" -issuer -noout -inform "${certificate_type}" | "${awk_cmd}" 'BEGIN {RS=", " } $0 ~ /^O =/ { print substr($0,5,21)}')
        if [ -z "$ssl_certificate_issuer" ]
        then
            ssl_certificate_issuer=$("${openssl_cmd}" x509 -in "${certificate_file}" -issuer -noout -inform "${certificate_type}" | "${awk_cmd}" 'BEGIN {RS="/" } $0 ~ /^O=/ { print substr($0,3,21)}')
        fi

        # get the common name (CN) from the X.509 certificate
        ssl_certificate_common_name=$("${openssl_cmd}" x509 -in "${certificate_file}" -subject -noout -inform "${certificate_type}" | "${sed_cmd}" -e 's/.*CN = //' | "${sed_cmd}" -e 's/, .*//')
        
        # fallback to a different command in case the previous one cannot extract the value
        if [[ $ssl_certificate_common_name == *"/"* ]]; then
            ssl_certificate_common_name=$("${openssl_cmd}" x509 -in "${certificate_file}" -subject -noout -inform "${certificate_type}" | "${sed_cmd}" -e 's/.*CN=//' | "${sed_cmd}" -e 's/, .*//')
        fi

        # get the serial number from the X.509 certificate
        ssl_certificate_serial_number=$("${openssl_cmd}" x509 -in "${certificate_file}" -serial -noout -inform "${certificate_type}" | "${sed_cmd}" -e 's/serial=//')
    fi

    # split the result into parameters, and pass the relevant pieces to date2julian
    set -- ${ssl_certificate_date}

    if [ "${certificate_type}" == "crt" ]; then

        month=$(getmonth "${2}")

        # convert the date to seconds, and get the diff between NOW and the expiration date
        cert_julian=$(date2julian "${month#0}" "${3#0}" "${6}")
        cert_diff=$(date_diff "${now_julian}" "${cert_julian}")
        certificate_status=''
        service_key=$(echo "${certificate_file}" | "${cut_cmd}" -d '/' -f 2)
        host="${serviceHostMapping[$service_key]}"
    else

        month=$(getmonth "${1}")

        # convert the date to seconds, and get the diff between NOW and the expiration date
        cert_julian=$(date2julian "${month#0}" "${2#0}" "${4}")
        cert_diff=$(date_diff "${now_julian}" "${cert_julian}")
        certificate_status=''
    fi

    if [ "${cert_diff}" -lt 0 ]; then

        certificate_status="Expired"
        return_code=2

    elif [ "${cert_diff}" -lt "${warning_threshold}" ]; then

        certificate_status="Expiring"
        return_code=1

    else
        certificate_status="Valid"
        return_code=0
    fi

    if [ "${certificate_type}" == "crt" ]; then
        min_date=$(echo "${ssl_certificate_date}" | "${awk_cmd}" '{ print $2, $3, $6 }')
    else
        min_date=$(echo "${ssl_certificate_date}" | "${awk_cmd}" '{ print $1, $2, $4 }')
    fi

    # dynamic JSON model for the certificate details object. This is going to be inserted in the 'certificatesList' array
    json_array_entry=$( jq -n \
                    --arg sn "${ssl_certificate_serial_number}" \
                    --arg cn "${ssl_certificate_common_name}" \
                    --arg iss "${ssl_certificate_issuer}" \
                    --arg hn "${host}" \
                    --arg st "${certificate_status}" \
                    --arg ed "${min_date}" \
                    --arg dte "${cert_diff}" \
                    '{serialNumber: $sn, ssl_certificate_common_name: $cn, issuer: $iss, hostName: $hn, status: $st, expiryDate: $ed, daysToExpire: $dte}' )
    
    # append the entry into the JSON array
    json_output+="${json_array_entry}"
    json_output+=","
}

# Entrypoint
while getopts abc:d:e:E:f:hik:nNp:qs:St:Vx: option
do
    case "${option}" in
        b) NOHEADER="TRUE";;
        c) certificate_file=${OPTARG};;
        d) certificates_folder=${OPTARG};;
        f) server_file=$OPTARG;;
        i) ISSUER="TRUE";;
        k) keystore_password=${OPTARG};;
        p) port=$OPTARG;;
        s) host=$OPTARG;;
        S) VALIDATION="TRUE";;
        t) certificate_type=$OPTARG;;
        x) warning_threshold=$OPTARG;;
       \?) echo 'Argument is not valid. Exiting...'
           exit 1;;
    esac
done

# Send along the servername when TLS is used
if ${openssl_cmd} s_client -help 2>&1 | grep '-servername' > /dev/null; then
    tls_server_name="TRUE"
else
    tls_server_name="FALSE"
fi

# Place to stash temporary files
certificate_temp_file=$($mktemp_cmd /var/tmp/cert.XXXXXX)
certificate_error_file=$($mktemp_cmd /var/tmp/error.XXXXXX)

# Baseline the dates so we have something to compare to
month=$(${date_cmd} "+%m")
day=$(${date_cmd} "+%d")
year=$(${date_cmd} "+%Y")
now_julian=$(date2julian "${month#0}" "${day#0}" "${year}")

# Touch the files prior to using them
if [ -n "${certificate_temp_file}" ] && [ -n "${certificate_error_file}" ]; then
    touch "${certificate_temp_file}" "${certificate_error_file}"
else
    echo "ERROR: Problem creating temporary files"
    echo "FIX: Check that mktemp works on your system"
    exit 1
fi

# if a host was passed on the cmdline, use that value
if [ "${host}" != "" ]; then

    check_server_status "${host}" "${port:=443}"

# if a file is passed to the "-f" option on the command line, check each certificate or server / port combination in the file to see if they are about to expire
elif [ -f "${server_file}" ]; then

    json_output+="${json_output_start}"

    IFS=$'\n'

    for line in $(grep -E -v '(^#|^$)' "${server_file}")
    do
        host=${line%% *}
        port=${line##* }

        IFS=" "

        if [ "$port" = "file" ]; then
            check_file_status "${host}" "file" "${host}"
        else
            check_server_status "${host}" "${port}"
        fi
    done

    IFS="${OLDIFS}"

    json_output="${json_output::-1}"
    json_output+="${json_output_end}"

    prints_as_json "domains-file-json-output.json"

# Check to see if the certificate in certificate_file is about to expire
elif [ "${certificate_file}" != "" ]; then

    json_output+="${json_output_start}"

    check_file_status "${certificate_file}" "file" "${certificate_file}"

    json_output="${json_output::-1}"
    json_output+="${json_output_end}"

    prints_as_json "keystore-file-json-output.json"

# Check to see if the certificates in certificates_folder are about to expire
elif [ "${certificates_folder}" != "" ] && ("${find_cmd}" -L "${certificates_folder}" -type f > /dev/null 2>&1); then

    json_output+="${json_output_start}"

    for file in $("${find_cmd}" -L "${certificates_folder}" -type f); do
        check_file_status "${file}" "file" "${file}"
    done

    json_output="${json_output::-1}"
    json_output+="${json_output_end}"

    prints_as_json "keystore-files-folder-json-output.json"

# There was an error, so print a detailed usage message and exit
else
    exit 1
fi
