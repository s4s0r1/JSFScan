#!/bin/bash

# Logo
logo() {
    echo " _______ ______ _______ ______                          _     "
    echo "(_______/ _____(_______/ _____)                        | |    "
    echo "     _ ( (____  _____ ( (____   ____ _____ ____     ___| |__  "
    echo " _  | | \\____ \|  ___) \____ \ / ___(____ |  _ \   /___|  _ \ "
    echo "| |_| | _____) | |     _____) ( (___/ ___ | | | |_|___ | | | |"
    echo " \___/ (______/|_|    (______/ \____\_____|_| |_(_(___/|_| |_|"
    echo "                                                              "
}

logo

# Gather JSFilesUrls
gather_js() {
    echo -e "\n[\e[32m+\e[0m] Started Gathering JsFiles-links\n"
    cat "$target" | gau | grep -iE "\.js$" | uniq | sort >> jsfile_links.txt
    cat "$target" | subjs >> jsfile_links.txt
    echo -e "\n[\e[32m+\e[0m] Checking for live JsFiles-links\n"
    cat jsfile_links.txt | httpx -follow-redirects -silent -status-code | grep "[200]" | cut -d ' ' -f1 | sort -u > live_jsfile_links.txt
}

# Open JSUrlFiles
open_jsurlfile() {
    echo -e "\n[\e[32m+\e[0m] Filtering JsFiles-links\n"
    cat "$target" | httpx -follow-redirects -silent -status-code | grep "[200]" | cut -d ' ' -f1 | sort -u > live_jsfile_links.txt
}

# Gather Endpoints From JsFiles
endpoint_js() {
    echo -e "\n[\e[32m+\e[0m] Started gathering Endpoints\n"
    interlace -tL live_jsfile_links.txt -threads 5 -c "echo 'Scanning _target_ Now' ; python3 ./tools/LinkFinder/linkfinder.py -d -i '_target_' -o cli >> endpoints.txt" -v
}

# Gather Secrets From Js Files
secret_js() {
    echo -e "\n[\e[32m+\e[0m] Started Finding Secrets in JSFiles\n"
    interlace -tL live_jsfile_links.txt -threads 5 -c "python3 ./tools/SecretFinder/SecretFinder.py -i '_target_' -o cli >> jslinksecret.txt" -v
}

# Collect Js Files For Manual Search
getjsbeautify() {
    echo -e "\n[\e[32m+\e[0m] Started to Gather JSFiles locally for Manual Testing\n"
    mkdir -p jsfiles
    interlace -tL live_jsfile_links.txt -threads 5 -c "bash ./tools/getjsbeautify.sh '_target_'" -v
    echo -e "\n[\e[32m+\e[0m] Manually Search For Secrets Using gf or grep in out/\n"
}

# Gather JSFilesWordlist
wordlist_js() {
    echo -e "\n[\e[32m+\e[0m] Started Gathering Words From JsFiles-links For Wordlist.\n"
    cat live_jsfile_links.txt | python3 ./tools/getjswords.py >> temp_jswordlist.txt
    sort -u temp_jswordlist.txt >> jswordlist.txt
    rm temp_jswordlist.txt
}

# Gather Variables from JSFiles For XSS
var_js() {
    echo -e "\n[\e[32m+\e[0m] Started Finding Variables in JSFiles For Possible XSS\n"
    while read -r url; do
        bash ./tools/jsvar.sh "$url" | tee -a js_var.txt
    done < live_jsfile_links.txt
}

# Find DomXSS
domxss_js() {
    echo -e "\n[\e[32m+\e[0m] Scanning JSFiles For Possible DomXSS\n"
    interlace -tL live_jsfile_links.txt -threads 5 -c "bash ./tools/findomxss.sh _target_" -v
}

# Generate Report
report() {
    echo -e "\n[\e[32m+\e[0m] Generating Report!\n"
    bash report.sh
}

# Save in Output Folder
output() {
    mkdir -p "$dir"
    mv endpoints.txt jsfile_links.txt jslinksecret.txt live_jsfile_links.txt jswordlist.txt js_var.txt domxss_scan.txt report.html "$dir/" 2>/dev/null
    mv jsfiles/ "$dir/"
}

while getopts ":l:f:esmwvdro:-:" opt; do
    case ${opt} in
    -)
        case "${OPTARG}" in
        all)
            endpoint_js
            secret_js
            getjsbeautify
            wordlist_js
            var_js
            domxss_js
            ;;
        *)
            if [ "$OPTERR" = 1 ] && [ "${optspec:0:1}" != ":" ]; then
                echo "Unknown option --${OPTARG}" >&2
            fi
            ;;
        esac
        ;;
    l)
        target=$OPTARG
        gather_js
        ;;
    f)
        target=$OPTARG
        open_jsurlfile
        ;;
    e)
        endpoint_js
        ;;
    s)
        secret_js
        ;;
    m)
        getjsbeautify
        ;;
    w)
        wordlist_js
        ;;
    v)
        var_js
        ;;
    d)
        domxss_js
        ;;
    r)
        report
        ;;
    o)
        dir=$OPTARG
        output
        ;;
    \? | h)
        echo "Usage: "
        echo "       -l   Gather Js Files Links"
        echo "       -f   Import File Containing JS Urls"
        echo "       -e   Gather Endpoints For JSFiles"
        echo "       -s   Find Secrets For JSFiles"
        echo "       -m   Fetch Js Files for manual testing"
        echo "       -o   Make an Output Directory to put all things Together"
        echo "       -w   Make a wordlist using words from jsfiles"
        echo "       -v   Extract Variables from the jsfiles"
        echo "       -d   Scan for Possible DomXSS from jsfiles"
        echo "       -r   Generate Scan Report in HTML"
        echo "       --all Scan Everything!"
        ;;
    :)
        echo "Invalid Options $OPTARG require an argument"
        ;;
    esac
done
shift $((OPTIND - 1))

# Fixing the code
