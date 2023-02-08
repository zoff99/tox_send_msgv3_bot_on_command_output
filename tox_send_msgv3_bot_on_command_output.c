/**
 * [tox send msgv3 bot]
 * Copyright (C) 2023 Zoff <zoff@zoff.cc>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 */

#define _GNU_SOURCE


#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <dirent.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <pthread.h>

#include <semaphore.h>
#include <signal.h>
#include <linux/sched.h>

#include "list.h"

#include <sodium/utils.h>

#include <tox/tox.h>
#include <curl/curl.h>

#define CURRENT_LOG_LEVEL 9 // 0 -> error, 1 -> warn, 2 -> info, 9 -> debug
FILE *logfile = NULL;

// const char *shell_command = "rsstail -p -P -i 3 -H -u https://github.com/openwrt/openwrt/releases.atom -n 2 -";
const char *shell_command = "./command.sh";

#define SPINS_UP_NUM 1
int spin = SPINS_UP_NUM;
uint8_t x = 1;
struct Tox* toxes[SPINS_UP_NUM];
int tox_shellcmd_thread_stop = 0;
int f_online = TOX_CONNECTION_NONE;
int self_online = TOX_CONNECTION_NONE;

const char *tokenFile = "./token.txt";
static char *NOTIFICATION__device_token = NULL;
static const char *NOTIFICATION_GOTIFY_UP_PREFIX = "https://";
pthread_t notification_thread;
int notification_thread_stop = 1;
int need_send_notification = 0;
#define SEND_PUSH_TRIED_FOR_1_MESSAGE_MAX 50
int send_notification_counter = SEND_PUSH_TRIED_FOR_1_MESSAGE_MAX;
const int read_buffer_size = TOX_MSGV3_MAX_MESSAGE_LENGTH;

struct stringlist {
    char *s; // free this one
    char *msgv3_id; // DO NOT free this one, since it points into "s" above
    size_t bytes;
};
list_t *list = NULL;
#define MAX_STRINGLIST_ENTRIES 50
pthread_mutex_t msg_lock;

typedef enum CONTROL_PROXY_MESSAGE_TYPE {
    CONTROL_PROXY_MESSAGE_TYPE_FRIEND_PUBKEY_FOR_PROXY = 175,
    CONTROL_PROXY_MESSAGE_TYPE_PROXY_PUBKEY_FOR_FRIEND = 176,
    CONTROL_PROXY_MESSAGE_TYPE_ALL_MESSAGES_SENT = 177,
    CONTROL_PROXY_MESSAGE_TYPE_PROXY_KILL_SWITCH = 178,
    CONTROL_PROXY_MESSAGE_TYPE_NOTIFICATION_TOKEN = 179,
    CONTROL_PROXY_MESSAGE_TYPE_PUSH_URL_FOR_FRIEND = 181
} CONTROL_PROXY_MESSAGE_TYPE;

struct Node1 {
    char *ip;
    char *key;
    uint16_t udp_port;
    uint16_t tcp_port;
} nodes1[] = {
{ "tox.novg.net", "D527E5847F8330D628DAB1814F0A422F6DC9D0A300E6C357634EE2DA88C35463", 33445, 33445 },
{ "bg.tox.dcntrlzd.network", "20AD2A54D70E827302CDF5F11D7C43FA0EC987042C36628E64B2B721A1426E36", 33445, 33445 },
{"91.219.59.156","8E7D0B859922EF569298B4D261A8CCB5FEA14FB91ED412A7603A585A25698832",33445,33445},
{"85.143.221.42","DA4E4ED4B697F2E9B000EEFE3A34B554ACD3F45F5C96EAEA2516DD7FF9AF7B43",33445,33445},
{"tox.initramfs.io","3F0A45A268367C1BEA652F258C85F4A66DA76BCAA667A49E770BCC4917AB6A25",33445,33445},
{"144.217.167.73","7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C",33445,33445},
{"tox.abilinski.com","10C00EB250C3233E343E2AEBA07115A5C28920E9C8D29492F6D00B29049EDC7E",33445,33445},
{"tox.novg.net","D527E5847F8330D628DAB1814F0A422F6DC9D0A300E6C357634EE2DA88C35463",33445,33445},
{"198.199.98.108","BEF0CFB37AF874BD17B9A8F9FE64C75521DB95A37D33C5BDB00E9CF58659C04F",33445,33445},
{"tox.kurnevsky.net","82EF82BA33445A1F91A7DB27189ECFC0C013E06E3DA71F588ED692BED625EC23",33445,33445},
{"81.169.136.229","E0DB78116AC6500398DDBA2AEEF3220BB116384CAB714C5D1FCD61EA2B69D75E",33445,33445},
{"205.185.115.131","3091C6BEB2A993F1C6300C16549FABA67098FF3D62C6D253828B531470B53D68",53,53},
{"bg.tox.dcntrlzd.network","20AD2A54D70E827302CDF5F11D7C43FA0EC987042C36628E64B2B721A1426E36",33445,33445},
{"46.101.197.175","CD133B521159541FB1D326DE9850F5E56A6C724B5B8E5EB5CD8D950408E95707",33445,33445},
{"tox1.mf-net.eu","B3E5FA80DC8EBD1149AD2AB35ED8B85BD546DEDE261CA593234C619249419506",33445,33445},
{"tox2.mf-net.eu","70EA214FDE161E7432530605213F18F7427DC773E276B3E317A07531F548545F",33445,33445},
{"195.201.7.101","B84E865125B4EC4C368CD047C72BCE447644A2DC31EF75BD2CDA345BFD310107",33445,33445},
{"tox4.plastiras.org","836D1DA2BE12FE0E669334E437BE3FB02806F1528C2B2782113E0910C7711409",33445,33445},
{"gt.sot-te.ch","F4F4856F1A311049E0262E9E0A160610284B434F46299988A9CB42BD3D494618",33445,33445},
{"188.225.9.167","1911341A83E02503AB1FD6561BD64AF3A9D6C3F12B5FBB656976B2E678644A67",33445,33445},
{"122.116.39.151","5716530A10D362867C8E87EE1CD5362A233BAFBBA4CF47FA73B7CAD368BD5E6E",33445,33445},
{"195.123.208.139","534A589BA7427C631773D13083570F529238211893640C99D1507300F055FE73",33445,33445},
{"tox3.plastiras.org","4B031C96673B6FF123269FF18F2847E1909A8A04642BBECD0189AC8AEEADAF64",33445,33445},
{"104.225.141.59","933BA20B2E258B4C0D475B6DECE90C7E827FE83EFA9655414E7841251B19A72C",43334,43334},
{"139.162.110.188","F76A11284547163889DDC89A7738CF271797BF5E5E220643E97AD3C7E7903D55",33445,33445},
{"198.98.49.206","28DB44A3CEEE69146469855DFFE5F54DA567F5D65E03EFB1D38BBAEFF2553255",33445,33445},
{"172.105.109.31","D46E97CF995DC1820B92B7D899E152A217D36ABE22730FEA4B6BF1BFC06C617C",33445,33445},
{"ru.tox.dcntrlzd.network","DBB2E896990ECC383DA2E68A01CA148105E34F9B3B9356F2FE2B5096FDB62762",33445,33445},
{"91.146.66.26","B5E7DAC610DBDE55F359C7F8690B294C8E4FCEC4385DE9525DBFA5523EAD9D53",33445,33445},
{"tox01.ky0uraku.xyz","FD04EB03ABC5FC5266A93D37B4D6D6171C9931176DC68736629552D8EF0DE174",33445,33445},
{"tox02.ky0uraku.xyz","D3D6D7C0C7009FC75406B0A49E475996C8C4F8BCE1E6FC5967DE427F8F600527",33445,33445},
{"tox.plastiras.org","8E8B63299B3D520FB377FE5100E65E3322F7AE5B20A0ACED2981769FC5B43725",33445,33445},
{"kusoneko.moe","BE7ED53CD924813507BA711FD40386062E6DC6F790EFA122C78F7CDEEE4B6D1B",33445,33445},
{"tox2.plastiras.org","B6626D386BE7E3ACA107B46F48A5C4D522D29281750D44A0CBA6A2721E79C951",33445,33445},
{"172.104.215.182","DA2BD927E01CD05EBCC2574EBE5BEBB10FF59AE0B2105A7D1E2B40E49BB20239",33445,33445},
    { NULL, NULL, 0, 0 }
};

struct Node2 {
    char *ip;
    char *key;
    uint16_t udp_port;
    uint16_t tcp_port;
} nodes2[] = {
{ "tox.novg.net", "D527E5847F8330D628DAB1814F0A422F6DC9D0A300E6C357634EE2DA88C35463", 33445, 33445 },
{ "bg.tox.dcntrlzd.network", "20AD2A54D70E827302CDF5F11D7C43FA0EC987042C36628E64B2B721A1426E36", 33445, 33445 },
{"91.219.59.156","8E7D0B859922EF569298B4D261A8CCB5FEA14FB91ED412A7603A585A25698832",33445,33445},
{"85.143.221.42","DA4E4ED4B697F2E9B000EEFE3A34B554ACD3F45F5C96EAEA2516DD7FF9AF7B43",33445,33445},
{"tox.initramfs.io","3F0A45A268367C1BEA652F258C85F4A66DA76BCAA667A49E770BCC4917AB6A25",33445,33445},
{"144.217.167.73","7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C",33445,33445},
{"tox.abilinski.com","10C00EB250C3233E343E2AEBA07115A5C28920E9C8D29492F6D00B29049EDC7E",33445,33445},
{"tox.novg.net","D527E5847F8330D628DAB1814F0A422F6DC9D0A300E6C357634EE2DA88C35463",33445,33445},
{"198.199.98.108","BEF0CFB37AF874BD17B9A8F9FE64C75521DB95A37D33C5BDB00E9CF58659C04F",33445,33445},
{"tox.kurnevsky.net","82EF82BA33445A1F91A7DB27189ECFC0C013E06E3DA71F588ED692BED625EC23",33445,33445},
{"81.169.136.229","E0DB78116AC6500398DDBA2AEEF3220BB116384CAB714C5D1FCD61EA2B69D75E",33445,33445},
{"205.185.115.131","3091C6BEB2A993F1C6300C16549FABA67098FF3D62C6D253828B531470B53D68",53,53},
{"bg.tox.dcntrlzd.network","20AD2A54D70E827302CDF5F11D7C43FA0EC987042C36628E64B2B721A1426E36",33445,33445},
{"46.101.197.175","CD133B521159541FB1D326DE9850F5E56A6C724B5B8E5EB5CD8D950408E95707",33445,33445},
{"tox1.mf-net.eu","B3E5FA80DC8EBD1149AD2AB35ED8B85BD546DEDE261CA593234C619249419506",33445,33445},
{"tox2.mf-net.eu","70EA214FDE161E7432530605213F18F7427DC773E276B3E317A07531F548545F",33445,33445},
{"195.201.7.101","B84E865125B4EC4C368CD047C72BCE447644A2DC31EF75BD2CDA345BFD310107",33445,33445},
{"tox4.plastiras.org","836D1DA2BE12FE0E669334E437BE3FB02806F1528C2B2782113E0910C7711409",33445,33445},
{"gt.sot-te.ch","F4F4856F1A311049E0262E9E0A160610284B434F46299988A9CB42BD3D494618",33445,33445},
{"188.225.9.167","1911341A83E02503AB1FD6561BD64AF3A9D6C3F12B5FBB656976B2E678644A67",33445,33445},
{"122.116.39.151","5716530A10D362867C8E87EE1CD5362A233BAFBBA4CF47FA73B7CAD368BD5E6E",33445,33445},
{"195.123.208.139","534A589BA7427C631773D13083570F529238211893640C99D1507300F055FE73",33445,33445},
{"tox3.plastiras.org","4B031C96673B6FF123269FF18F2847E1909A8A04642BBECD0189AC8AEEADAF64",33445,33445},
{"104.225.141.59","933BA20B2E258B4C0D475B6DECE90C7E827FE83EFA9655414E7841251B19A72C",43334,43334},
{"139.162.110.188","F76A11284547163889DDC89A7738CF271797BF5E5E220643E97AD3C7E7903D55",33445,33445},
{"198.98.49.206","28DB44A3CEEE69146469855DFFE5F54DA567F5D65E03EFB1D38BBAEFF2553255",33445,33445},
{"172.105.109.31","D46E97CF995DC1820B92B7D899E152A217D36ABE22730FEA4B6BF1BFC06C617C",33445,33445},
{"ru.tox.dcntrlzd.network","DBB2E896990ECC383DA2E68A01CA148105E34F9B3B9356F2FE2B5096FDB62762",33445,33445},
{"91.146.66.26","B5E7DAC610DBDE55F359C7F8690B294C8E4FCEC4385DE9525DBFA5523EAD9D53",33445,33445},
{"tox01.ky0uraku.xyz","FD04EB03ABC5FC5266A93D37B4D6D6171C9931176DC68736629552D8EF0DE174",33445,33445},
{"tox02.ky0uraku.xyz","D3D6D7C0C7009FC75406B0A49E475996C8C4F8BCE1E6FC5967DE427F8F600527",33445,33445},
{"tox.plastiras.org","8E8B63299B3D520FB377FE5100E65E3322F7AE5B20A0ACED2981769FC5B43725",33445,33445},
{"kusoneko.moe","BE7ED53CD924813507BA711FD40386062E6DC6F790EFA122C78F7CDEEE4B6D1B",33445,33445},
{"tox2.plastiras.org","B6626D386BE7E3ACA107B46F48A5C4D522D29281750D44A0CBA6A2721E79C951",33445,33445},
{"172.104.215.182","DA2BD927E01CD05EBCC2574EBE5BEBB10FF59AE0B2105A7D1E2B40E49BB20239",33445,33445},
    { NULL, NULL, 0, 0 }
};


#define CLEAR(x) memset(&(x), 0, sizeof(x))

static void ping_push_service();

void dbg(int level, const char *fmt, ...)
{
    char *level_and_format = NULL;
    char *fmt_copy = NULL;

    if (fmt == NULL)
    {
        return;
    }

    if (strlen(fmt) < 1)
    {
        return;
    }

    if (!logfile)
    {
        return;
    }

    if ((level < 0) || (level > 9))
    {
        level = 0;
    }

    level_and_format = calloc(1, strlen(fmt) + 3 + 1);

    if (!level_and_format)
    {
        // dbg(9, stderr, "free:000a\n");
        return;
    }

    fmt_copy = level_and_format + 2;
    strcpy(fmt_copy, fmt);
    level_and_format[1] = ':';

    if (level == 0)
    {
        level_and_format[0] = 'E';
    }
    else if (level == 1)
    {
        level_and_format[0] = 'W';
    }
    else if (level == 2)
    {
        level_and_format[0] = 'I';
    }
    else
    {
        level_and_format[0] = 'D';
    }

    level_and_format[(strlen(fmt) + 2)] = '\0'; // '\0' or '\n'
    level_and_format[(strlen(fmt) + 3)] = '\0';
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t t3 = time(NULL);
    struct tm tm3 = *localtime(&t3);
    char *level_and_format_2 = calloc(1, strlen(level_and_format) + 5 + 3 + 3 + 1 + 3 + 3 + 3 + 7 + 1);
    level_and_format_2[0] = '\0';
    snprintf(level_and_format_2, (strlen(level_and_format) + 5 + 3 + 3 + 1 + 3 + 3 + 3 + 7 + 1),
             "%04d-%02d-%02d %02d:%02d:%02d.%06ld:%s",
             tm3.tm_year + 1900, tm3.tm_mon + 1, tm3.tm_mday,
             tm3.tm_hour, tm3.tm_min, tm3.tm_sec, tv.tv_usec, level_and_format);

    if (level <= CURRENT_LOG_LEVEL)
    {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(logfile, level_and_format_2, ap);
        va_end(ap);
    }

    // dbg(9, "free:001\n");
    if (level_and_format)
    {
        // dbg(9, "free:001.a\n");
        free(level_and_format);
    }

    if (level_and_format_2)
    {
        free(level_and_format_2);
    }

    // dbg(9, "free:002\n");
}

void tox_log_cb__custom1(Tox *tox, TOX_LOG_LEVEL level, const char *file, uint32_t line, const char *func,
                        const char *message, void *user_data)
{
    dbg(9, "C-TOXCORE:1:%d:%s:%d:%s:%s\n", (int)level, file, (int)line, func, message);
}

void tox_log_cb__custom2(Tox *tox, TOX_LOG_LEVEL level, const char *file, uint32_t line, const char *func,
                        const char *message, void *user_data)
{
    dbg(9, "C-TOXCORE:2:%d:%s:%d:%s:%s\n", (int)level, file, (int)line, func, message);
}

static uint32_t list_items()
{
    if (!list)
    {
        return 0;
    }

    uint32_t count = 0;
    list_node_t *nodex;
    list_iterator_t *it = list_iterator_new(list, LIST_HEAD);
    while ((nodex = list_iterator_next(it)))
    {
        count++;
    }
    list_iterator_destroy(it);
    return count;
}

static void hex_string_to_bin2(const char *hex_string, uint8_t *output) {
    size_t len = strlen(hex_string) / 2;
    size_t i = len;
    if (!output) {
        return;
    }

    const char *pos = hex_string;

    for (i = 0; i < len; ++i, pos += 2) {
        sscanf(pos, "%2hhx", &output[i]);
    }
}

static void update_savedata_file(const Tox *tox, int num)
{
    size_t size = tox_get_savedata_size(tox);
    char *savedata = calloc(1, size);
    tox_get_savedata(tox, (uint8_t *)savedata);


    char *savedata_filename1 = calloc(1, 1000);
    int ret_snprintf = snprintf(savedata_filename1, 900, "savedata_%d.tox", num);
    FILE *f = NULL;
    f = fopen(savedata_filename1, "wb");
    fwrite(savedata, size, 1, f);
    fclose(f);
    free(savedata_filename1);

    free(savedata);
}

void yieldcpu(uint32_t ms)
{
    usleep(1000 * ms);
}

static Tox* tox_init(int num)
{
    Tox *tox = NULL;
    struct Tox_Options options;
    tox_options_default(&options);

    // ----- set options ------
    options.ipv6_enabled = false;
    options.local_discovery_enabled = true;
    options.hole_punching_enabled = true;
    options.udp_enabled = true;
    options.tcp_port = 0; // disable tcp relay function!
    // ----- set options ------

    char *savedata_filename1 = calloc(1, 1000);
    int ret_snprintf = snprintf(savedata_filename1, 900, "savedata_%d.tox", num);
    FILE *f = NULL;
    f = fopen(savedata_filename1, "rb");

    if (f)
    {
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);
        uint8_t *savedata = calloc(1, fsize);
        size_t dummy = fread(savedata, fsize, 1, f);

        if (dummy < 1)
        {
            dbg(0, "reading savedata failed\n");
        }

        fclose(f);
        options.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;
        options.savedata_data = savedata;
        options.savedata_length = fsize;
    }

    if (num == 1)
    {
        options.log_callback = tox_log_cb__custom1;
    }
    else
    {
        options.log_callback = tox_log_cb__custom2;
    }

    tox = tox_new(&options, NULL);
    free(savedata_filename1);
    return tox;
}

static bool tox_connect(Tox *tox, int num) {

    dbg(9, "[%d]:bootstrapping ...\n", num);

    if (num == 1)
    {
        for (int i = 0; nodes1[i].ip; i++) {
            uint8_t *key = (uint8_t *)calloc(1, 100);
            hex_string_to_bin2(nodes1[i].key, key);
            if (!key) {
                return false; // Return because it will most likely fail again
            }

            tox_bootstrap(tox, nodes1[i].ip, nodes1[i].udp_port, key, NULL);
            if (nodes1[i].tcp_port != 0) {
                tox_add_tcp_relay(tox, nodes1[i].ip, nodes1[i].tcp_port, key, NULL);
            }
            free(key);
        }
    }
    else
    {
        for (int i = 0; nodes2[i].ip; i++) {
            uint8_t *key = (uint8_t *)calloc(1, 100);
            hex_string_to_bin2(nodes2[i].key, key);
            if (!key) {
                return false; // Return because it will most likely fail again
            }

            tox_bootstrap(tox, nodes2[i].ip, nodes2[i].udp_port, key, NULL);
            if (nodes2[i].tcp_port != 0) {
                tox_add_tcp_relay(tox, nodes2[i].ip, nodes2[i].tcp_port, key, NULL);
            }
            free(key);
        }
    }
    dbg(9, "[%d]:bootstrapping done.\n", num);

    return true;
}

static void to_hex(char *out, uint8_t *in, int size) {
    while (size--) {
        if (*in >> 4 < 0xA) {
            *out++ = '0' + (*in >> 4);
        } else {
            *out++ = 'A' + (*in >> 4) - 0xA;
        }

        if ((*in & 0xf) < 0xA) {
            *out++ = '0' + (*in & 0xF);
        } else {
            *out++ = 'A' + (*in & 0xF) - 0xA;
        }
        in++;
    }
}

static bool file_exists(const char *path)
{
    struct stat s;
    return stat(path, &s) == 0;
}

static void add_token(const char *token_str)
{
    if (file_exists(tokenFile))
    {
        dbg(2, "Tokenfile already exists, deleting it\n");
        unlink(tokenFile);
    }

    FILE *f = fopen(tokenFile, "wb");

    if (f)
    {
        fwrite(token_str, strlen(token_str), 1, f);
        dbg(2, "saved token:%s\n", NOTIFICATION__device_token);
        fclose(f);
    }
}

static void read_token_from_file()
{
    if (!file_exists(tokenFile))
    {
        return;
    }

    FILE *f = fopen(tokenFile, "rb");

    if (! f)
    {
        return;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize < 1)
    {
        fclose(f);
        return;
    }

    if (NOTIFICATION__device_token)
    {
        free(NOTIFICATION__device_token);
        NOTIFICATION__device_token = NULL;
    }

    NOTIFICATION__device_token = calloc(1, fsize + 2);
    size_t res = fread(NOTIFICATION__device_token, fsize, 1, f);
    if (res) {}

    dbg(2, "loaded token:%s\n", NOTIFICATION__device_token);

    fclose(f);
}

static void self_connection_change_callback(Tox *tox, TOX_CONNECTION status, void *userdata) {
    tox;
    uint8_t* unum = (uint8_t *)userdata;
    uint8_t num = *unum;

    switch (status) {
        case TOX_CONNECTION_NONE:
            dbg(9, "[%d]:Lost connection to the Tox network.\n", num);
            break;
        case TOX_CONNECTION_TCP:
            dbg(9, "[%d]:Connected using TCP.\n", num);
            break;
        case TOX_CONNECTION_UDP:
            dbg(9, "[%d]:Connected using UDP.\n", num);
            break;
    }

    self_online = status;
}

void bin2upHex(const uint8_t *bin, uint32_t bin_size, char *hex, uint32_t hex_size)
{
    sodium_bin2hex(hex, hex_size, bin, bin_size);

    for (size_t i = 0; i < hex_size - 1; i++)
    {
        hex[i] = toupper(hex[i]);
    }
}

static bool compare_m3_id(const uint8_t *id1, const uint8_t *id2)
{
    // -------------------
    int length = 32;
    int msg_hex_size = (length * 2) + 1;

    char msg_hex[msg_hex_size + 1];
    CLEAR(msg_hex);
    bin2upHex((const uint8_t *)id1, length, msg_hex, msg_hex_size);

    char msg_hex2[msg_hex_size + 1];
    CLEAR(msg_hex2);
    bin2upHex((const uint8_t *)id2, length, msg_hex2, msg_hex_size);

    dbg(0, "m3:id1_hex=%s id2_hex=%s\n", msg_hex, msg_hex2);
    // -------------------

    const int tox_public_key_bin_size = 32;
    int res = strncmp(id1, id2, tox_public_key_bin_size);
    if (res == 0)
    {
        dbg(0, "m3:*equal*\n");
        return true;
    }
    else
    {
        dbg(0, "m3:NOT EQUAL\n");
        return false;
    }
}

static void check_m3_id(const uint8_t *message)
{
    list_node_t *node = list_at(list, 0);
    if (node)
    {
        if (compare_m3_id(message, ((struct stringlist*)(node->val))->msgv3_id))
        {
            dbg(0, "incoming Message:check_m3_id:slot ZERO id found\n");
            free(((struct stringlist*)(node->val))->s);
            list_remove(list, node);
        }
    }
}

static void friend_message_callback(Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type, const uint8_t *message, size_t length,
                       void *user_data)
{
    dbg(2, "incoming Message: type=%d fnum=%d\n", type, friend_number);

    int msg_hex_size = (length * 2) + 1;
    char msg_hex[msg_hex_size + 1];
    CLEAR(msg_hex);
    bin2upHex((const uint8_t *)message, length, msg_hex, msg_hex_size);
    dbg(0, "incoming Message:msg_hex=%s\n", msg_hex);

    if (type == TOX_MESSAGE_TYPE_HIGH_LEVEL_ACK)
    {
        pthread_mutex_lock(&msg_lock);
        if (list_items() > 0)
        {
            dbg(0, "incoming Message:check:slot 0\n");
            check_m3_id(message + 3);
        }
        pthread_mutex_unlock(&msg_lock);
    }
    else
    {
        // HINT: check if this is a msgV3 message and then send an ACK back
        if ((message) && (length > (TOX_MSGV3_MSGID_LENGTH + TOX_MSGV3_TIMESTAMP_LENGTH + TOX_MSGV3_GUARD)))
        {
            dbg(0, "incoming Message:check:1:msgv3\n");
            int pos = length - (TOX_MSGV3_MSGID_LENGTH + TOX_MSGV3_TIMESTAMP_LENGTH + TOX_MSGV3_GUARD);

            // check for guard
            uint8_t g1 = *(message + pos);
            uint8_t g2 = *(message + pos + 1);

            // check for the msgv3 guard
            if ((g1 == 0) && (g2 == 0))
            {
                dbg(0, "incoming Message:check:2:msgv3\n");
                size_t msgv3_ack_length = 1 + 2 + 32 + 4;
                uint8_t *msgv3_ack_buffer = (uint8_t *)calloc(1, msgv3_ack_length + 1);
                if (msgv3_ack_buffer)
                {
                    uint8_t *p = msgv3_ack_buffer;
                    memcpy(p, "_", 1);
                    p = p + 1;
                    p = p + 2;
                    memcpy(p, (message + 3), TOX_MSGV3_MSGID_LENGTH);
                    uint32_t res = tox_friend_send_message(tox, friend_number, TOX_MESSAGE_TYPE_HIGH_LEVEL_ACK, msgv3_ack_buffer, msgv3_ack_length, NULL);
                    dbg(0, "incoming Message:msgv3:send ACK:res=%d\n", res);
                    free(msgv3_ack_buffer);
                }
            }
        }
    }
}

static void friend_connection_status_callback(Tox *tox, uint32_t friend_number, Tox_Connection connection_status,
        void *userdata)
{
    tox;
    uint8_t* unum = (uint8_t *)userdata;
    uint8_t num = *unum;

    switch (connection_status) {
        case TOX_CONNECTION_NONE:
            dbg(9, "[%d]:Lost connection to friend %d\n", num, friend_number);
            break;
        case TOX_CONNECTION_TCP:
            dbg(9, "[%d]:Connected to friend %d using TCP\n", num, friend_number);
            break;
        case TOX_CONNECTION_UDP:
            dbg(9, "[%d]:Connected to friend %d using UDP\n", num, friend_number);
            break;
    }

    f_online = connection_status;
}

static void friend_request_callback(Tox *tox, const uint8_t *public_key, const uint8_t *message, size_t length,
                                   void *userdata) {
    tox;
    uint8_t* unum = (uint8_t *)userdata;
    uint8_t num = *unum;

    TOX_ERR_FRIEND_ADD err;
    tox_friend_add_norequest(tox, public_key, &err);
    dbg(9, "[%d]:accepting friend request. res=%d\n", num, err);
    update_savedata_file(tox, 0);
}

static void friend_lossless_packet_cb(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length, void *user_data)
{
    dbg(9, "enter friend_lossless_packet_cb:pktid=%d\n", data[0]);

    if (length == 0) {
        dbg(0, "received empty lossless package!\n");
        return;
    }

    if (data[0] == CONTROL_PROXY_MESSAGE_TYPE_PUSH_URL_FOR_FRIEND)
    {
            dbg(0, "received CONTROL_PROXY_MESSAGE_TYPE_NOTIFICATION_TOKEN message\n");
            NOTIFICATION__device_token = calloc(1, (length + 1));
            memcpy(NOTIFICATION__device_token, (data + 1), (length - 1));
            dbg(0, "CONTROL_PROXY_MESSAGE_TYPE_NOTIFICATION_TOKEN: %s\n", NOTIFICATION__device_token);
            // save notification token to file
            add_token(NOTIFICATION__device_token);
    }
}

static void set_cb(Tox *tox1)
{
    // ---------- CALLBACKS ----------
    tox_callback_self_connection_status(tox1, self_connection_change_callback);
    tox_callback_friend_connection_status(tox1, friend_connection_status_callback);
    tox_callback_friend_request(tox1, friend_request_callback);
    tox_callback_friend_message(tox1, friend_message_callback);
    tox_callback_friend_lossless_packet(tox1, friend_lossless_packet_cb);
    // ---------- CALLBACKS ----------
}


static size_t xnet_pack_u16(uint8_t *bytes, uint16_t v)
{
    bytes[0] = (v >> 8) & 0xff;
    bytes[1] = v & 0xff;
    return sizeof(v);
}

static size_t xnet_pack_u32(uint8_t *bytes, uint32_t v)
{
    uint8_t *p = bytes;
    p += xnet_pack_u16(p, (v >> 16) & 0xffff);
    p += xnet_pack_u16(p, v & 0xffff);
    return p - bytes;
}

static time_t get_unix_time(void)
{
    return time(NULL);
}

static void m3(const char *message_text, int message_text_bytes)
{
    uint8_t *msgv3_out_bin = calloc(1, read_buffer_size + 1); // plus 1 for a null byte at the end always
    if (!msgv3_out_bin)
    {
        dbg(0, "m3:error allocating memory\n");
        return;
    }

    memcpy(msgv3_out_bin, message_text, message_text_bytes);
    msgv3_out_bin[message_text_bytes] = 0;
    msgv3_out_bin[message_text_bytes + 1] = 0;
    int id_pos = message_text_bytes + 2;
    tox_messagev3_get_new_message_id(msgv3_out_bin + id_pos);

    uint32_t timestamp_unix = (uint32_t)get_unix_time();
    uint32_t timestamp_unix_buf = 0;
    xnet_pack_u32((uint8_t *)&timestamp_unix_buf, timestamp_unix);
    memcpy(msgv3_out_bin + (id_pos + 32), &timestamp_unix_buf, (size_t)(TOX_MSGV3_TIMESTAMP_LENGTH));

    int length = message_text_bytes + 2 + 32 + 4;
    int msg_hex_size = (length * 2) + 1;
    char msg_hex[msg_hex_size + 1];
    CLEAR(msg_hex);
    bin2upHex((const uint8_t *)msgv3_out_bin, length, msg_hex, msg_hex_size);
    dbg(0, "m3:txtlen=%d msg_hex=%s msg_str=%s\n", message_text_bytes, msg_hex, msgv3_out_bin);

    struct stringlist* item = calloc(1, sizeof(struct stringlist));
    if (item)
    {
        item->s = msgv3_out_bin;
        item->msgv3_id = msgv3_out_bin + id_pos;
        item->bytes = message_text_bytes + 2 + 32 + 4;
        list_node_t *node = list_node_new(item);
        list_rpush(list, node);
    }
    else
    {
        dbg(0, "m3:error allocating memory for list item\n");
    }
}


void *thread_shell_command(void *data)
{
    Tox *t = (Tox*) data;
    pthread_t id = pthread_self();

    int read_bytes = 0;
    char cmd[1000];
    CLEAR(cmd);

    snprintf(cmd, sizeof(cmd), "%s </dev/null 2>/dev/null", shell_command);

    // Open a pipe with the shell command
    FILE *pipein = popen(cmd, "r");

    uint8_t *read_buffer = calloc(1, read_buffer_size + 1); // plus 1 for a null byte at the end always
    while (tox_shellcmd_thread_stop != 1)
    {
        memset(read_buffer, 0, read_buffer_size);
        fgets((char *)read_buffer, read_buffer_size, pipein);
        if (read_buffer[strlen(read_buffer) - 1] == '\n')
        {
            read_buffer[strlen(read_buffer) - 1] = '\0'; // remove the newline
            if (strlen(read_buffer) > 0)
            {
                dbg(0, "LINE::len=%d text=%s\n", strlen(read_buffer), read_buffer);
                pthread_mutex_lock(&msg_lock);
                if (list_items() < MAX_STRINGLIST_ENTRIES)
                {
                    dbg(0, "adding string to buffer\n");
                    m3(read_buffer, strlen(read_buffer));
                    send_notification_counter = SEND_PUSH_TRIED_FOR_1_MESSAGE_MAX;
                    dbg(9, "thread_shell_command:send_notification_counter=%d\n", send_notification_counter);
                }
                else
                {
                    dbg(0, "string buffer full, dropping string\n");
                }
                pthread_mutex_unlock(&msg_lock);
            }
        }
        else
        {
            // line was truncated
            // dbg(0, "str_buf:line was truncated:LINE=%s\n", read_buffer);
        }

        yieldcpu(100); // pause for x ms
    }

    free(read_buffer);
    pclose(pipein);
    dbg(2, "Tox:shell command thread exit!\n");
    return NULL;
}

void send_m3(int slot_num, Tox *tox)
{
    list_node_t *node = list_at(list, 0);
    if (node)
    {
        struct stringlist* sl = (struct stringlist*)(node->val);
        Tox_Err_Friend_Send_Message error;
        tox_friend_send_message(tox, 0, TOX_MESSAGE_TYPE_NORMAL,
                                    (const uint8_t *)sl->s,
                                         sl->bytes,
                                         &error);

        dbg(2, "send_m3:len=%d str=%s\n", sl->bytes, (const uint8_t *)sl->s);
        ping_push_service();
    }
}

static void print_stats(Tox *tox, int num)
{
    uint32_t num_friends = tox_self_get_friend_list_size(tox);
    dbg(9, "[%d]:tox num_friends:%d\n", num, num_friends);
}










struct string {
    char *ptr;
    size_t len;
};

static void init_string(struct string *s)
{
    s->len = 0;
    s->ptr = calloc(1, s->len + 1);

    if (s->ptr == NULL)
    {
        dbg(9, "malloc() failed\n");
        exit(EXIT_FAILURE);
    }

    s->ptr[0] = '\0';
}

static size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s)
{
    size_t new_len = s->len + size*nmemb;
    s->ptr = realloc(s->ptr, new_len+1);

    if (s->ptr == NULL)
    {
        dbg(9, "realloc() failed\n");
        exit(EXIT_FAILURE);
    }

    memcpy(s->ptr+s->len, ptr, size*nmemb);
    s->ptr[new_len] = '\0';
    s->len = new_len;

    return size*nmemb;
}

static void ping_push_service()
{
    dbg(9, "ping_push_service\n");

    if (!NOTIFICATION__device_token)
    {
        dbg(9, "ping_push_service: No NOTIFICATION__device_token\n");
        return;
    }

    need_send_notification = 1;
}

static void *notification_thread_func(void *data)
{
    while (notification_thread_stop == 0)
    {
        if (need_send_notification == 1)
        {
            if (!NOTIFICATION__device_token)
            {
                // no notification token
            }
            else
            {
                dbg(9, "ping_push_service:NOTIFICATION_METHOD GOTIFY_UP\n");
                int result = 1;
                CURL *curl = NULL;
                CURLcode res = 0;

                size_t max_buf_len = strlen(NOTIFICATION__device_token) + 1;

                if (
                    (max_buf_len <= strlen(NOTIFICATION_GOTIFY_UP_PREFIX))
                    ||
                    (strncmp(NOTIFICATION_GOTIFY_UP_PREFIX, NOTIFICATION__device_token, strlen(NOTIFICATION_GOTIFY_UP_PREFIX)) != 0)
                   )
                {
                    // HINT: token does not start with "https://"
                }
                else
                {
                    if (send_notification_counter >= 0)
                    {
                        char buf[max_buf_len + 1];
                        memset(buf, 0, max_buf_len + 1);
                        snprintf(buf, max_buf_len, "%s", NOTIFICATION__device_token);

                        curl = curl_easy_init();

                        if (curl)
                        {
                            struct string s;
                            init_string(&s);

                            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "ping=1");
                            curl_easy_setopt(curl, CURLOPT_URL, buf);
                            curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0");

                            dbg(9, "request=%s\n", buf);

                            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
                            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);

                            res = curl_easy_perform(curl);

                            if (res != CURLE_OK)
                            {
                                dbg(9, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                            }
                            else
                            {
                                long http_code = 0;
                                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
                                if ((http_code < 300) && (http_code > 199))
                                {
                                    dbg(9, "server_answer:OK:CURLINFO_RESPONSE_CODE=%ld, %s\n", http_code, s.ptr);
                                    result = 0;
                                }
                                else
                                {
                                    dbg(9, "server_answer:ERROR:CURLINFO_RESPONSE_CODE=%ld, %s\n", http_code, s.ptr);
                                    result = 0; // do not retry, or the server may be spammed
                                }
                                free(s.ptr);
                                s.ptr = NULL;
                            }

                            curl_easy_cleanup(curl);
                        }
                    }
                    else
                    {
                        // dbg(9, "server_answer:NO send:send_notification_counter = %d\n", send_notification_counter);
                    }

                    if (result == 0)
                    {
                        dbg(9, "server_answer:need_send_notification -> reset\n");
                        need_send_notification = 0;

                        pthread_mutex_lock(&msg_lock);
                        send_notification_counter--;
                        if (send_notification_counter < 0)
                        {
                            send_notification_counter = 0;
                        }
                        dbg(9, "server_answer:send_notification_counter=%d\n", send_notification_counter);
                        pthread_mutex_unlock(&msg_lock);
                    }
                }
            }
        }
        yieldcpu(500); // sleep 500 ms
    }

    dbg(2, "Notification:Clean thread exit!\n");
    pthread_exit(0);
}






int main(void)
{
    logfile = stdout;
    setvbuf(logfile, NULL, _IOLBF, 0);
    dbg(9, "--start--\n");

	if (pthread_mutex_init(&msg_lock, NULL) != 0)
	{
		dbg(0, "Error creating msg_lock\n");
	}
	else
	{
		dbg(2, "msg_lock created successfully\n");
	}

    f_online = TOX_CONNECTION_NONE;
    self_online = TOX_CONNECTION_NONE;

    read_token_from_file();

    list = list_new();

    uint32_t last_send_msg_timestamp_unix = 0;
    uint8_t k = 0;
    toxes[k] = tox_init(k);
    dbg(9, "[%d]:ID:1: %p\n", k, toxes[k]);

    const char *name = "Tox Command Ping";
    tox_self_set_name(toxes[k], (uint8_t *) name, strlen(name), NULL);

    const char *status_message = "Pings you on new output";
    tox_self_set_status_message(toxes[k], (uint8_t *) status_message, strlen(status_message), NULL);


    uint8_t public_key_bin1[TOX_ADDRESS_SIZE];
    char    public_key_str1[TOX_ADDRESS_SIZE * 2];
    tox_self_get_address(toxes[k], public_key_bin1);
    to_hex(public_key_str1, public_key_bin1, TOX_ADDRESS_SIZE);
    dbg(9, "[%d]:ID:1: %.*s\n", k, TOX_ADDRESS_SIZE * 2, public_key_str1);

    tox_connect(toxes[k], 1);
    set_cb(toxes[k]);

    tox_iterate(toxes[k], &x);

    print_stats(toxes[k], 1);


    need_send_notification = 0;
    send_notification_counter = SEND_PUSH_TRIED_FOR_1_MESSAGE_MAX;
    notification_thread_stop = 0;

    if (pthread_create(&notification_thread, NULL, notification_thread_func, (void *)NULL) != 0)
    {
        dbg(0, "Notification Thread create failed\n");
    }
    else
    {
        pthread_setname_np(notification_thread, "t_notif");
        dbg(2, "Notification Thread successfully created\n");
    }


    pthread_t tid[1];
    tox_shellcmd_thread_stop = 0;
    if (pthread_create(&(tid[0]), NULL, thread_shell_command, (void *)toxes[k]) != 0)
    {
        dbg(0, "shell command thread Thread create failed\n");
    }
    else
    {
        pthread_setname_np(tid[0], "t_shell");
        dbg(2, "shell command thread Thread successfully created\n");
    }


    long send_msg_iters = 80000;
    long send_msg_cur_iter = send_msg_iters - 10;

    long save_iters = 800000;
    long counter = save_iters - 10;

    long bootstrap_iters = 30000;
    long bootstrap_counter = 0;

    while (1 == 1) {
        counter++;
        send_msg_cur_iter++;
        tox_iterate(toxes[k], &x);

        if (self_online == TOX_CONNECTION_NONE)
        {
            bootstrap_counter++;
            if (bootstrap_counter >= bootstrap_iters)
            {
                tox_connect(toxes[k], 1);
                bootstrap_counter = 0;
            }
        }

        if (counter >= save_iters)
        {
            update_savedata_file(toxes[k], k);
            // dbg(9, "[%d]:ID:1: saving data\n", k);
        }
        if (counter >= save_iters)
        {
            counter = 0;
        }

        if (send_msg_cur_iter >= send_msg_iters)
        {
            pthread_mutex_lock(&msg_lock);
            if (f_online != TOX_CONNECTION_NONE)
            {
                if (list_items() > 0)
                {
                    // HINT: send only every 2 s, to perserve message ordering my timestamp upto the seconds
                    if ((uint32_t)get_unix_time() > (last_send_msg_timestamp_unix + 1))
                    {
                        dbg(9, "send_m3:times %d %d\n", (uint32_t)get_unix_time(), (last_send_msg_timestamp_unix + 1));
                        dbg(9, "send_m3 slot 0\n");
                        send_m3(0, toxes[k]);
                        last_send_msg_timestamp_unix = (uint32_t)get_unix_time();
                    }
                    else
                    {
                        dbg(9, "send_m3:pause for 1 second\n");
                    }
                }
            }
            else
            {
                if (list_items() > 0)
                {
                    dbg(9, "ping_push_service -> (%d >= %d)\n", send_msg_cur_iter, send_msg_iters);
                    ping_push_service();
                }
            }
            pthread_mutex_unlock(&msg_lock);
            send_msg_cur_iter = 0;
        }

        usleep(tox_iteration_interval(toxes[0]));
    }

    tox_shellcmd_thread_stop = 1;
    pthread_join(tid[0], NULL);

    notification_thread_stop = 1;
    pthread_join(notification_thread, NULL);

    tox_kill(toxes[k]);

    list_destroy(list);

    fclose(logfile);

    return 0;
} 


