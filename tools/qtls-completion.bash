#!/bin/bash
# Q-TLS CLI Bash Completion

_qtls_completion() {
    local cur prev commands

    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # 메인 명령어
    commands="keygen certgen quickstart verify info version help"

    # keygen 알고리즘
    keygen_algorithms="kyber512 kyber768 kyber1024 dilithium2 dilithium3 dilithium5"

    # certgen 타입
    certgen_types="ca server client"

    # 현재 명령어
    local command="${COMP_WORDS[1]}"

    case "${COMP_CWORD}" in
        1)
            # 메인 명령어 자동완성
            COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
            return 0
            ;;
        2)
            # 서브명령어별 자동완성
            case "${command}" in
                keygen)
                    COMPREPLY=( $(compgen -W "${keygen_algorithms}" -- ${cur}) )
                    return 0
                    ;;
                certgen)
                    COMPREPLY=( $(compgen -W "${certgen_types}" -- ${cur}) )
                    return 0
                    ;;
            esac
            ;;
    esac

    # 옵션 자동완성
    case "${prev}" in
        -o|--output|-d|--dir|-cn|--common-name|-a|--algorithm|--ca-cert|--ca-key|--san|--days)
            # 파일/디렉토리 이름은 수동 입력
            COMPREPLY=()
            return 0
            ;;
        *)
            # 일반 옵션
            local opts="-o --output -d --dir -v --verbose -h --help"

            case "${command}" in
                keygen)
                    opts="-o --output -d --dir -v --verbose -h --help"
                    ;;
                certgen)
                    opts="-cn --common-name -o --output -d --dir -a --algorithm --days --ca-cert --ca-key --san -v --verbose -h --help"
                    ;;
                quickstart)
                    opts="-d --dir -cn --server-cn -a --algorithm -v --verbose -h --help"
                    ;;
            esac

            COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
            return 0
            ;;
    esac
}

complete -F _qtls_completion qtls
