#!/bin/bash

# Copyright (c) iduosi@icloud.com, All rights reserved.
# description: netover's project made netover.
# homepage: https://netover.com

EXTEND_PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH=${PATH}:${EXTEND_PATH}

DATETIME_FORMAT=`date -d "today" +"%Y-%m-%d %H:%M:%S"`

GL_DEPS_PACKAGE_PATH=_deps_packages
GL_THE_FILENAME=
GL_THE_FILEPATH=
GL_QUIT=
[[ ${SHLVL} = 1 ]] && GL_QUIT=return || GL_QUIT=exit

GL_DEPS_LIBSODIUM_VERSION="libsodium-1.0.17"
GL_DEPS_LIBSODIUM_DOWNLOAD_URL="https://github.com/jedisct1/libsodium/releases/download/1.0.17/libsodium-1.0.17.tar.gz"

#
# 控制台有色输出函数：
#   \e 或 \033 = 打开反斜杠ESC转义
#   Format: \033[第一个参数-背景色;第二个参数-前景色;第三个参数-第四个参数-m
#       Like: 红色字体输出 = \\033[1;31m$1
#       第一个参数: 0 透明使用终端颜色; 1 高亮 40 黑; 41 红; 42 绿; 43 黄; 44 蓝; 45 紫; 46 青绿; 47白灰
#       第二个参数：30 黑; 31 红; 32 绿; 33 黄; 34 蓝; 35 紫; 36 青绿; 37 白灰
#       第三个参数：高亮是1; 不高亮是0
#       第四个参数为m: m后面紧跟字符串
#
#   恢复默认颜色输出配置：\\033[0m\n
#
function FUN_ERROR_MSG()
{
    local msg=$1
    local filter_pre=$2

    if [[ "x${filter_pre}" == "xF" ]]; then
        printf "\\033[0;31;1m${msg}\\033[0m\n"
    else
        printf "\\033[0;31;1m[${DATETIME_FORMAT}] ERROR: ${msg}\\033[0m\n"
    fi
}
function FUN_WARN_MSG()
{
    local msg=$1
    local filter_pre=$2

    if [[ "x${filter_pre}" == "xF" ]]; then
        printf "\\033[0;33;1m${msg}\\033[0m\n"
    else
        printf "\\033[0;33;1m[${DATETIME_FORMAT}] WARN: ${msg}\\033[0m\n"
    fi
}
function FUN_INFO_MSG()
{
    local msg=$1
    local filter_pre=$2

    if [[ "x${filter_pre}" == "xF" ]]; then
        printf "\\033[0;32;1m${msg}\\033[0m\n"
    else
        printf "\\033[0;32;1m[${DATETIME_FORMAT}] INFO: ${msg}\\033[0m\n"
    fi
}

if [ $(id -u) != "0" ]; then
    FUN_ERROR_MSG "u must be root to run this script, please use root[command: sudo su | su root | sudo ./]." "F"
    ${GL_QUIT} 1
fi

echo "$0" | grep -q "bash"
_bash_run_type=$?
if [ ${_bash_run_type} -eq 0 ]; then
    FUN_ERROR_MSG "please use execute './[bash-filename].sh' bash." "F"
    ${GL_QUIT} 1
else
    if [ ${0:0:1} = "/" ]; then
        _THE_FILE=$0
    else
        _THE_FILE=$(pwd)/$0
    fi

    cd "$(dirname "${_THE_FILE}")"
    GL_THE_FILEPATH=$PWD
    GL_DEPS_PACKAGE_PATH="${GL_THE_FILEPATH}/_deps_packages"
    GL_THE_FILENAME="${_THE_FILE##*/}"
    cd - > /dev/null
fi

echo
FUN_INFO_MSG "GLOBAL var print:" "F"
FUN_INFO_MSG "GL_DEPS_PACKAGE_PATH: ${GL_DEPS_PACKAGE_PATH}" "F"
FUN_INFO_MSG "GL_THE_FILENAME: ${GL_THE_FILENAME}" "F"
FUN_INFO_MSG "GL_THE_FILEPATH: ${GL_THE_FILEPATH}" "F"
FUN_INFO_MSG "GL_QUIT: ${GL_QUIT}" "F"
FUN_INFO_MSG "GL_DEPS_LIBSODIUM_VERSION: ${GL_DEPS_LIBSODIUM_VERSION}" "F"
FUN_INFO_MSG "GL_DEPS_LIBSODIUM_DOWNLOAD_URL: ${GL_DEPS_LIBSODIUM_DOWNLOAD_URL}" "F"
echo

GL_USE_METHODCIPHERS=(
aes-256-gcm
aes-192-gcm
aes-128-gcm
aes-256-ctr
aes-192-ctr
aes-128-ctr
aes-256-cfb
aes-192-cfb
aes-128-cfb
camellia-128-cfb
camellia-192-cfb
camellia-256-cfb
chacha20-ietf-poly1305
chacha20-ietf
chacha20
rc4-md5
)

# DEFINE-FUNCTION:
#   FUN_DISABLE_SELINUX: turn-off SELINUX, like use command: setenforce 0.
function FUN_DISABLE_SELINUX()
{
    if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

# DEFINE-FUNCTION:
#   FUN_CHECK_OS_OPTION: check system option is allow or deny.
#
# Input&Output help:
#   @param check_type : the first param
#   @param check_type_value : the second param
#   @return 0 | 1 : result of check option, true or false
#
# Usage help:
#   FUN_CHECK_OS_OPTION system_release centos
#   FUN_CHECK_OS_OPTION system_package_manager yum
function FUN_CHECK_OS_OPTION()
{
    local check_type=$1
    local check_type_value=$2
    local system_release=
    local system_package_manager=

    if [[ -f /etc/redhat-release ]]; then
        system_release="centos"
        system_package_manager="yum"
    elif grep -Eqi "debian" /etc/issue; then
        system_release="debian"
        system_package_manager="apt"
    elif grep -Eqi "ubuntu" /etc/issue; then
        system_release="ubuntu"
        system_package_manager="apt"
    elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
        system_release="centos"
        system_package_manager="yum"
    elif grep -Eqi "debian" /proc/version; then
        system_release="debian"
        system_package_manager="apt"
    elif grep -Eqi "ubuntu" /proc/version; then
        system_release="ubuntu"
        system_package_manager="apt"
    elif grep -Eqi "centos|red hat|redhat" /proc/version; then
        system_release="centos"
        system_package_manager="yum"
    fi

    if [[ "${check_type}" == "system_release" ]]; then
        if [ "${check_type_value}" == "${system_release}" ]; then
            return 0
        else
            return 1
        fi
    elif [[ "${check_type}" == "system_package_manager" ]]; then
        if [ "${check_type_value}" == "${system_package_manager}" ]; then
            return 0
        else
            return 1
        fi
    fi
}

# DEFINE-FUNCTION:
#   FUN_GET_OS_VERSION: return current system os version string.
#
# Usage help:
#   local os_version="$(FUN_GET_OS_VERSION)"
function FUN_GET_OS_VERSION()
{
    if [[ -s /etc/redhat-release ]]; then
        grep -oE  "[0-9.]+" /etc/redhat-release
    else
        grep -oE  "[0-9.]+" /etc/issue
    fi
}

# DEFINE-FUNCTION:
#   FUN_CHECK_CENTOS_VERSION: check centos version is formated with input param.
#
# Input&Output help:
#   @param version : the first param
#   @return 0 | 1 : result of check option, true or false
#
# Usage help:
#   if FUN_CHECK_CENTOS_VERSION 5; then
#       # yes code segment
#   else
#       # no code segment
#   fi
function FUN_CHECK_CENTOS_VERSION()
{
    if FUN_CHECK_OS_OPTION system_release centos; then
        local version=$1
        local current_version="$(FUN_GET_OS_VERSION)"
        local main_current_version=${current_version%%.*}
        if [ "x${main_current_version}" == "x${version}" ]; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

# DEFINE-FUNCTION:
#   FUN_GET_PUBLIC_IP_ADDRESS: return current machine public ip address.
#
# Usage help:
#   local public_ip_address="$(FUN_GET_PUBLIC_IP_ADDRESS)"
function FUN_GET_PUBLIC_IP_ADDRESS()
{
    local ip_address=$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
    [ -z ${ip_address} ] && ip_address=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
    [ -z ${ip_address} ] && ip_address=$( wget -qO- -t1 -T2 ipinfo.io/ip )
    [ ! -z ${ip_address} ] && echo ${ip_address} || echo
}

# DEFINE-FUNCTION:
#   FUN_GET_INPUT_CHAR: return input char from console shell.
#
# Usage help:
#   local read_char="$(FUN_GET_INPUT_CHAR)"
function FUN_GET_INPUT_CHAR()
{
    SAVEDSTTY=`stty -g`
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2> /dev/null
    stty -raw
    stty echo
    stty $SAVEDSTTY
}

# DEFINE-FUNCTION:
#   FUN_CLEANUP_ALL: clean all files from dependency_package.
function FUN_CLEANUP_ALL()
{
    cd ${GL_DEPS_PACKAGE_PATH}
    # rm -rf !(.vendor.txt)
    rm -rf ${GL_DEPS_LIBSODIUM_VERSION}.tar.gz ${GL_DEPS_LIBSODIUM_VERSION}
    cd ${GL_THE_FILEPATH}
}

# DEFINE-FUNCTION:
#   FUN_DOWNLOAD_PACKAGES: download package to dependency_package.
#
# Usage help:
#   FUN_DOWNLOAD_PACKAGES libsodium
function FUN_DOWNLOAD_PACKAGES()
{
    local package_type=$1
    case "${package_type}" in
    "libsodium")
        FUN_INFO_MSG "u will download ${GL_DEPS_LIBSODIUM_VERSION}.tar.gz to ${GL_DEPS_PACKAGE_PATH}."
        # deps package: libsodium
        if ! wget --no-check-certificate -O ${GL_DEPS_PACKAGE_PATH}/${GL_DEPS_LIBSODIUM_VERSION}.tar.gz ${GL_DEPS_LIBSODIUM_DOWNLOAD_URL}; then
            FUN_ERROR_MSG "Failed to download ${GL_DEPS_LIBSODIUM_VERSION}.tar.gz!" "F"
            ${GL_QUIT} 1
        fi
        ;;
    *)
        FUN_INFO_MSG "No input, will download nothing."
    esac
}

GL_SERVE_PORT=10248
GL_USE_PASSWORD="OGRhYzI3YzU1"
GL_USE_METHOD="aes-256-cfb"

# DEFINE-FUNCTION:
#   FUN_PRE_INSTALL: pre install, do something.
function FUN_PRE_INSTALL()
{
    local need_conf_serve_option="n"
    local conf_serve_port=$(shuf -i 10000-30000 -n 1)
    local conf_serve_pass=$(date +%s | sha256sum | base64 | head -c 12 ; echo)

    FUN_INFO_MSG "If u don't want to config your owner running option..., you can skip it with default config." "F"
    FUN_INFO_MSG "Do you want to config running option? (y/n)" "F"
    read -p "(Default: n):" need_conf_serve_option

    [ -z ${need_conf_serve_option} ] && need_conf_serve_option="n"

    if [ "${need_conf_serve_option}" == "y" ] || [ "${need_conf_serve_option}" == "Y" ]; then
        FUN_INFO_MSG "Please enter password for netoversocks" "F"
        read -p "(Default password: ${conf_serve_pass}):" GL_USE_PASSWORD

        [ -z "${GL_USE_PASSWORD}" ] && GL_USE_PASSWORD="${conf_serve_pass}"
        echo
        FUN_INFO_MSG "Configure serve password = ${GL_SERVE_PORT}" "F"
        echo

        while true
        do
            FUN_INFO_MSG "Please enter a port for netoversocks [1000-65535]" "F"
            read -p "(Default port: ${conf_serve_port}):" GL_SERVE_PORT

            [ -z "${GL_SERVE_PORT}" ] && GL_SERVE_PORT=${conf_serve_port}

            expr ${GL_SERVE_PORT} + 1 &>/dev/null

            if [ $? -eq 0 ]; then
                if [ ${GL_SERVE_PORT} -ge 1000 ] && [ ${GL_SERVE_PORT} -le 65535 ] && [ ${GL_SERVE_PORT:0:1} != 0 ]; then
                    echo
                    FUN_INFO_MSG "Configure serve port = ${GL_SERVE_PORT}" "F"
                    echo
                    break
                fi
            fi

            FUN_ERROR_MSG "Please enter a correct number [1000-65535]."
        done

        while true
        do
            FUN_INFO_MSG "Please select stream cipher for netoversocks, like aes-256-cfb" "F"

            local cipher_item_loop=
            local cipher_item_selected=

            for ((i=1; i<=${#GL_USE_METHODCIPHERS[@]}; i++)); do
                cipher_item_loop="${GL_USE_METHODCIPHERS[$i-1]}"

                FUN_INFO_MSG "[${i}] ${cipher_item_loop}" "F"
            done

            read -p "Which cipher you'd select(Default: ${GL_USE_METHODCIPHERS[0]}):" cipher_item_selected

            [ -z "${cipher_item_selected}" ] && cipher_item_selected=1
            expr ${cipher_item_selected} + 1 &>/dev/null

            if [ $? -ne 0 ]; then
                FUN_ERROR_MSG "Please enter a number."
                continue
            fi

            if [[ "${cipher_item_selected}" -lt 1 || "${cipher_item_selected}" -gt ${#GL_USE_METHODCIPHERS[@]} ]]; then
                FUN_ERROR_MSG "Please enter a number between 1 and ${#GL_USE_METHODCIPHERS[@]}" "F"
                continue
            fi

            GL_USE_METHOD=${GL_USE_METHODCIPHERS[${cipher_item_selected}-1]}

            echo
            FUN_INFO_MSG "GL_USE_METHOD = ${GL_USE_METHOD}" "F"
            echo
            break
        done
    fi

    if FUN_CHECK_OS_OPTION system_package_manager yum || FUN_CHECK_OS_OPTION system_package_manager apt; then
        # NOW we not support CentOS 5/6
        if FUN_CHECK_CENTOS_VERSION 5 || FUN_CHECK_CENTOS_VERSION 6; then
            FUN_ERROR_MSG "Not supported CentOS[5/6], please use it with CentOS7+/Debian7+/Ubuntu12+, and try again!" "F"
            ${GL_QUIT} 1
        fi
    else
        FUN_ERROR_MSG "Not supported os-system, please use it with CentOS7+/Debian7+/Ubuntu12+, and try again!" "F"
        ${GL_QUIT} 1
    fi

    FUN_INFO_MSG "Press any key to start...or Press Ctrl+C to cancel" "F"
    _char=`FUN_GET_INPUT_CHAR`

    if FUN_CHECK_OS_OPTION system_package_manager yum; then
        yum install -y openssl openssl-devel curl wget unzip gcc automake autoconf make libtool
        yum install -y python python-devel python-setuptools
    elif FUN_CHECK_OS_OPTION system_package_manager apt; then
        apt-get -y update
        apt-get -y install openssl libssl-dev curl wget unzip gcc automake autoconf make libtool
        apt-get -y install python python-dev python-setuptools
    fi

    cd ${GL_THE_FILEPATH}
}

# DEFINE-FUNCTION:
#   FUN_CONF: pre install, configure file.
function FUN_CONF()
{
    if [ -f ${GL_THE_FILEPATH}/netoversocks.json ]; then
        rm -f ${GL_THE_FILEPATH}/netoversocks.json
    fi

    if [ ! -f ${GL_THE_FILEPATH}/netoversocks.json ]; then
        cat > ${GL_THE_FILEPATH}/netoversocks.json<<-EOF
{
    "server":"0.0.0.0",
    "server_port":${GL_SERVE_PORT},
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"${GL_USE_PASSWORD}",
    "timeout":300,
    "method":"${GL_USE_METHOD}",
    "fast_open":false
}
EOF
    fi
}

# DEFINE-FUNCTION:
#   FUN_FIREWALLD_SETTING: pre install, firewall&iptables setting.
function FUN_FIREWALLD_SETTING()
{
    local setting_firewall_case="n"

    FUN_INFO_MSG "Firewall setting, if you use aliyuncloud|tencentcloud|digitalocean|googlecloud..., you can skip it." "F"
    FUN_INFO_MSG "Are you sure to set firewall about server port route? (y/n)" "F"
    read -p "(Default: n):" setting_firewall_case

    [ -z ${setting_firewall_case} ] && setting_firewall_case="n"

    if [ "${setting_firewall_case}" == "y" ] || [ "${setting_firewall_case}" == "Y" ]; then
        if FUN_CHECK_CENTOS_VERSION 7; then
            systemctl status firewalld > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                firewall-cmd --permanent --zone=public --add-port=${GL_SERVE_PORT}/tcp
                firewall-cmd --permanent --zone=public --add-port=${GL_SERVE_PORT}/udp
                firewall-cmd --reload
            else
                FUN_ERROR_MSG "Failed to set firewalld, please enable port ${GL_SERVE_PORT} manually if necessary!"
            fi
        fi
        FUN_INFO_MSG "Firewall set completed success."
    fi
}

# DEFINE-FUNCTION:
#   FUN_INSTALL: install, netoversocks setup.py install.
function FUN_INSTALL()
{
    if [ ! -f /usr/lib/libsodium.a ]; then
        cd ${GL_DEPS_PACKAGE_PATH}
        tar zxf ${GL_DEPS_LIBSODIUM_VERSION}.tar.gz

        cd ${GL_DEPS_LIBSODIUM_VERSION}
        ./configure --prefix=/usr && make && make install

        if [ $? -ne 0 ]; then
            FUN_CLEANUP_ALL
            FUN_ERROR_MSG "Failed to install libsodium!" "F"
            ${GL_QUIT} 1
        fi
    fi

    cd ${GL_THE_FILEPATH}

    ldconfig
    cd ${GL_THE_FILEPATH}/netoversocks
    python setup.py install --record ${GL_THE_FILEPATH}/install.log

    cd ${GL_THE_FILEPATH}
    if [ ! -f /etc/init.d/netoversocks ]; then
        if FUN_CHECK_OS_OPTION system_package_manager yum; then
            cp ${GL_THE_FILEPATH}/service/netoversocks-centos /etc/init.d/netoversocks
        fi
        if FUN_CHECK_OS_OPTION system_package_manager apt; then
            cp ${GL_THE_FILEPATH}/service/netoversocks-debian /etc/init.d/netoversocks
        fi
    fi
    if [ ! -f /etc/init.d/netoversocks ]; then
        FUN_ERROR_MSG "Failed to handle netoversocks chkconfig file!" "F"
        ${GL_QUIT} 1
    fi

    if [ ! -f /etc/netoversocks.json ]; then
        cp ${GL_THE_FILEPATH}/netoversocks.json /etc/netoversocks.json
    fi
    if [ ! -f /etc/netoversocks.json ]; then
        FUN_ERROR_MSG "Failed to handle netoversocks config file!" "F"
        ${GL_QUIT} 1
    fi
    cd ${GL_THE_FILEPATH}

    cd ${GL_THE_FILEPATH}
    if [ -f /usr/bin/noserver ] || [ -f /usr/local/bin/noserver ]; then
        chmod +x /etc/init.d/netoversocks
        if FUN_CHECK_OS_OPTION system_package_manager yum; then
            chkconfig --add netoversocks
            chkconfig netoversocks on
        elif FUN_CHECK_OS_OPTION system_package_manager apt; then
            update-rc.d -f netoversocks defaults
        fi
        /etc/init.d/netoversocks start
    else
        FUN_CLEANUP_ALL
        FUN_ERROR_MSG "Failed to install netoversocks!" "F"
        ${GL_QUIT} 1
    fi
    cd ${GL_THE_FILEPATH}

    echo
    FUN_INFO_MSG "Congratulation to install netover server!" "F"
    FUN_INFO_MSG "Serve address-IP: $(FUN_GET_PUBLIC_IP_ADDRESS)" "F"
    FUN_INFO_MSG "Serve listen-port: ${GL_SERVE_PORT}" "F"
    FUN_INFO_MSG "Serve used-password: ${GL_USE_PASSWORD}" "F"
    FUN_INFO_MSG "Serve encryption-method: ${GL_USE_METHOD}" "F"
    echo
    FUN_INFO_MSG "Tks, enjoy it~~~" "F"
    echo
}

# DEFINE-FUNCTION:
#   FUN_UNINSTALL: uninstall, rm installed's netoversocks files.
function FUN_UNINSTALL()
{
    local uninstall_case=

    printf "Are you sure to uninstall? (y/n)"
    printf "\n"
    read -p "(Default: n):" uninstall_case

    [ -z ${uninstall_case} ] && uninstall_case="n"

    if [ "${uninstall_case}" == "y" ] || [ "${uninstall_case}" == "Y" ]; then
        ps -ef | grep -v grep | grep -i "noserver" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            /etc/init.d/netoversocks stop
        fi

        if FUN_CHECK_OS_OPTION system_package_manager yum; then
            chkconfig --del netoversocks
        elif FUN_CHECK_OS_OPTION system_package_manager apt; then
            update-rc.d -f netoversocks remove
        fi

        rm -f /etc/netoversocks.json
        rm -f /var/run/netoversocks.pid
        rm -f /etc/init.d/netoversocks
        rm -f /var/log/netoversocks.log

        if [ -f ${GL_THE_FILEPATH}/install.log ]; then
            cat ${GL_THE_FILEPATH}/install.log | xargs rm -rf
        fi
        if [ -f ${GL_THE_FILEPATH}/install.log ]; then
            rm -f ${GL_THE_FILEPATH}/install.log
        fi

        FUN_INFO_MSG "success to uninstall!"
    else
        FUN_WARN_MSG "uninstall cancelled, nothing to do..."
    fi
}

# DEFINE-FUNCTION:
#   FUN_INSTALL_MAIN: main install.
function FUN_INSTALL_MAIN()
{
    FUN_CLEANUP_ALL

    FUN_DISABLE_SELINUX

    FUN_PRE_INSTALL

    if [ ! -f /usr/lib/libsodium.a ]; then
        FUN_DOWNLOAD_PACKAGES libsodium
    fi

    FUN_CONF

    FUN_FIREWALLD_SETTING

    FUN_INSTALL

    FUN_CLEANUP_ALL
}

# DEFINE-FUNCTION:
#   FUN_UNINSTALL_MAIN: main uninstall.
function FUN_UNINSTALL_MAIN()
{
    FUN_UNINSTALL
}

function FUN_TEST_OPTION_SETTING()
{
    local need_conf_serve_option="n"
    local conf_serve_port=$(shuf -i 10000-30000 -n 1)
    local conf_serve_pass=$(date +%s | sha256sum | base64 | head -c 12 ; echo)

    FUN_INFO_MSG "If u don't want to config your owner running option..., you can skip it with default config." "F"
    FUN_INFO_MSG "Do you want to config running option? (y/n)" "F"
    read -p "(Default: n):" need_conf_serve_option

    [ -z ${need_conf_serve_option} ] && need_conf_serve_option="n"

    if [ "${need_conf_serve_option}" == "y" ] || [ "${need_conf_serve_option}" == "Y" ]; then
        FUN_INFO_MSG "Please enter password for netoversocks" "F"
        read -p "(Default password: ${conf_serve_pass}):" GL_USE_PASSWORD

        [ -z "${GL_USE_PASSWORD}" ] && GL_USE_PASSWORD="${conf_serve_pass}"
        echo
        FUN_INFO_MSG "Configure serve password = ${GL_SERVE_PORT}" "F"
        echo

        while true
        do
            FUN_INFO_MSG "Please enter a port for netoversocks [1000-65535]" "F"
            read -p "(Default port: ${conf_serve_port}):" GL_SERVE_PORT

            [ -z "${GL_SERVE_PORT}" ] && GL_SERVE_PORT=${conf_serve_port}

            expr ${GL_SERVE_PORT} + 1 &>/dev/null

            if [ $? -eq 0 ]; then
                if [ ${GL_SERVE_PORT} -ge 1000 ] && [ ${GL_SERVE_PORT} -le 65535 ] && [ ${GL_SERVE_PORT:0:1} != 0 ]; then
                    echo
                    FUN_INFO_MSG "Configure serve port = ${GL_SERVE_PORT}" "F"
                    echo
                    break
                fi
            fi

            FUN_ERROR_MSG "Please enter a correct number [1000-65535]."
        done

        while true
        do
            FUN_INFO_MSG "Please select stream cipher for netoversocks, like aes-256-cfb" "F"

            local cipher_item_loop=
            local cipher_item_selected=

            for ((i=1; i<=${#GL_USE_METHODCIPHERS[@]}; i++)); do
                cipher_item_loop="${GL_USE_METHODCIPHERS[$i-1]}"

                FUN_INFO_MSG "[${i}] ${cipher_item_loop}" "F"
            done

            read -p "Which cipher you'd select(Default: ${GL_USE_METHODCIPHERS[0]}):" cipher_item_selected

            [ -z "${cipher_item_selected}" ] && cipher_item_selected=1
            expr ${cipher_item_selected} + 1 &>/dev/null

            if [ $? -ne 0 ]; then
                FUN_ERROR_MSG "Please enter a number."
                continue
            fi

            if [[ "${cipher_item_selected}" -lt 1 || "${cipher_item_selected}" -gt ${#GL_USE_METHODCIPHERS[@]} ]]; then
                FUN_ERROR_MSG "Please enter a number between 1 and ${#GL_USE_METHODCIPHERS[@]}" "F"
                continue
            fi

            GL_USE_METHOD=${GL_USE_METHODCIPHERS[${cipher_item_selected}-1]}

            echo
            FUN_INFO_MSG "GL_USE_METHOD = ${GL_USE_METHOD}" "F"
            echo
            break
        done
    fi

    echo
    FUN_INFO_MSG "Congratulation to install netover server!" "F"
    FUN_INFO_MSG "Serve address-IP: $(FUN_GET_PUBLIC_IP_ADDRESS)" "F"
    FUN_INFO_MSG "Serve listen-port: ${GL_SERVE_PORT}" "F"
    FUN_INFO_MSG "Serve used-password: ${GL_USE_PASSWORD}" "F"
    FUN_INFO_MSG "Serve encryption-method: ${GL_USE_METHOD}" "F"
    echo
}
########################################################################################################################
#
# Usage: install.sh [install|uninstall]
#
########################################################################################################################
_action=$1
[ -z $1 ] && _action=install
case "x${_action}" in
    "xinstall")
        FUN_INSTALL_MAIN
        ;;
    "xuninstall")
        FUN_UNINSTALL_MAIN
        ;;
    *)
        FUN_ERROR_MSG "Arguments error, [${_action}]" "F"
        FUN_INFO_MSG "Usage: `basename $0` [install|uninstall]" "F"
    ;;
esac
