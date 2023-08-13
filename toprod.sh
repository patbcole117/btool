#!/bin/bash

msg=''
tag=''

main() {

    while getopts 'm:t:' opt; do
        case "${opt}" in
            m) msg=${OPTARG} ;;
            t) tag=${OPTARG} ;;
            *) usage ;;
        esac
    done
    
    if [[ $# == 0 ]]; then
        usage
    fi

    git add .

    if [[ ${msg} != '' ]]; then
    #    echo "\"${msg}\""
        git commit -a -m "${msg}"
    #    git push
    fi

    if [[ ${tag} != '' ]]; then
        echo ${tag}
    #    git tag ${tag}
    #    git push origin ${tag}
    fi
    exit 0
}   

usage() {
    echo ""
    echo "usage: $0 [ -m | -t ] [ \"Commit message.\" | \"Tag\" ]" 1>&2
    echo ""
    exit 1
}

main "$@"
