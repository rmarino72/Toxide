// Minimal toxcore peer driven over stdin/stdout, for Toxide interop tests.
// Usage: toxpeer <port> [savefile [passphrase]]
// Commands (stdin, one per line):
//   BOOTSTRAP <ip> <port> <dht-key-hex>
//   ADD <toxid-hex> <message...>
//   ACCEPT <pk-hex>
//   MSG <friend> <text...>
//   NAME <text...>
//   STATUSMSG <text...>
//   SAVE <file>
//   SAVEENC <file> <passphrase>   (toxencryptsave format)
//   FILESEND <friend> <size> <name>  (content: byte i = (i * 31 + 7) & 0xff)
//   QUIT
// Events (stdout): READY <address> <dhtid> <port>, SELF <conn>, REQUEST <pk> <msg>, CONN <f> <conn>,
//   MSG <f> <type> <text>, RECEIPT <f> <id>, NAME <f> <name>, STATUSMSG <f> <text>, SENT <id>, ERR <...>
//   FILERECV <f> <file> <kind> <size> <name> (auto-accepted), FILEDONE <f> <file> <bytes> <sha256>,
//   FILESENDING <f> <file>, FILESENT <f> <file>, FILECTRL <f> <file> <control>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>
#include <time.h>
#include "toxcore/tox.h"
#include "toxencryptsave/toxencryptsave.h"
#include <sodium.h>

static void hex(const uint8_t *d, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02X", d[i]);
    out[2 * n] = 0;
}
static int unhex(const char *s, uint8_t *out, size_t n) {
    if (strlen(s) < 2 * n) return -1;
    for (size_t i = 0; i < n; i++) { unsigned v; if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1; out[i] = (uint8_t)v; }
    return 0;
}

static void on_self(Tox *t, TOX_CONNECTION c, void *u) { printf("SELF %d\n", c); fflush(stdout); }
static void on_request(Tox *t, const uint8_t *pk, const uint8_t *m, size_t len, void *u) {
    char h[65]; hex(pk, 32, h); printf("REQUEST %s %.*s\n", h, (int)len, m); fflush(stdout);
}
static void on_conn(Tox *t, uint32_t f, TOX_CONNECTION c, void *u) { printf("CONN %u %d\n", f, c); fflush(stdout); }
static void on_msg(Tox *t, uint32_t f, TOX_MESSAGE_TYPE ty, const uint8_t *m, size_t len, void *u) {
    printf("MSG %u %d %.*s\n", f, ty, (int)len, m); fflush(stdout);
}
static void on_receipt(Tox *t, uint32_t f, uint32_t id, void *u) { printf("RECEIPT %u %u\n", f, id); fflush(stdout); }
static void on_name(Tox *t, uint32_t f, const uint8_t *n, size_t len, void *u) {
    printf("NAME %u %.*s\n", f, (int)len, n); fflush(stdout);
}
static void on_statusmsg(Tox *t, uint32_t f, const uint8_t *n, size_t len, void *u) {
    printf("STATUSMSG %u %.*s\n", f, (int)len, n); fflush(stdout);
}
// One incoming and one outgoing file at a time is enough for the tests.
static uint8_t *recv_buf; static size_t recv_len;
static uint64_t send_size;

static uint8_t pattern(uint64_t i) { return (uint8_t)((i * 31 + 7) & 0xff); }

static void on_file_recv(Tox *t, uint32_t f, uint32_t file, uint32_t kind, uint64_t size, const uint8_t *name, size_t len, void *u) {
    printf("FILERECV %u %u %u %llu %.*s\n", f, file, kind, (unsigned long long)size, (int)len, name); fflush(stdout);
    free(recv_buf); recv_buf = malloc(size ? size : 1); recv_len = 0;
    tox_file_control(t, f, file, TOX_FILE_CONTROL_RESUME, NULL);
}
static void on_file_chunk(Tox *t, uint32_t f, uint32_t file, uint64_t pos, const uint8_t *data, size_t len, void *u) {
    if (len == 0) {
        uint8_t h[32]; char hh[65];
        crypto_hash_sha256(h, recv_buf, recv_len); hex(h, 32, hh);
        printf("FILEDONE %u %u %zu %s\n", f, file, recv_len, hh); fflush(stdout);
        return;
    }
    memcpy(recv_buf + pos, data, len);
    if (pos + len > recv_len) recv_len = pos + len;
}
static void on_chunk_request(Tox *t, uint32_t f, uint32_t file, uint64_t pos, size_t len, void *u) {
    if (len == 0) { printf("FILESENT %u %u\n", f, file); fflush(stdout); return; }
    uint8_t *buf = malloc(len);
    for (size_t i = 0; i < len; i++) buf[i] = pattern(pos + i);
    Tox_Err_File_Send_Chunk e; tox_file_send_chunk(t, f, file, pos, buf, len, &e);
    if (e) { printf("ERR chunk %d\n", e); fflush(stdout); }
    free(buf);
}
static void on_file_control(Tox *t, uint32_t f, uint32_t file, TOX_FILE_CONTROL c, void *u) {
    printf("FILECTRL %u %u %d\n", f, file, c); fflush(stdout);
}

static void on_log(Tox *t, TOX_LOG_LEVEL l, const char *file, uint32_t line, const char *func, const char *msg, void *u) {
    if (getenv("TOXPEER_LOG")) fprintf(stderr, "[%d] %s:%u %s: %s\n", l, file, line, func, msg);
}

int main(int argc, char **argv) {
    setvbuf(stdin, NULL, _IONBF, 0); // select() + buffered stdio would strand queued commands
    uint16_t port = argc > 1 ? (uint16_t)atoi(argv[1]) : 33445;
    struct Tox_Options *o = tox_options_new(NULL);
    tox_options_set_local_discovery_enabled(o, getenv("TOXPEER_LAN") != NULL);
    tox_options_set_start_port(o, port);
    tox_options_set_end_port(o, port);
    tox_options_set_log_callback(o, on_log);

    uint8_t *saved = NULL;
    if (argc > 2) {
        FILE *f = fopen(argv[2], "rb");
        if (f) {
            fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
            saved = malloc(n); fread(saved, 1, n, f); fclose(f);
            if (argc > 3) { // encrypted profile: argv[3] is the passphrase
                uint8_t *plain = malloc(n);
                Tox_Err_Decryption de;
                if (!tox_pass_decrypt(saved, n, (const uint8_t *)argv[3], strlen(argv[3]), plain, &de)) {
                    printf("ERR decrypt %d\n", de); fflush(stdout); return 1;
                }
                saved = plain; n -= TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
            }
            tox_options_set_savedata_type(o, TOX_SAVEDATA_TYPE_TOX_SAVE);
            tox_options_set_savedata_data(o, saved, n);
        }
    }

    Tox_Err_New err;
    Tox *tox = tox_new(o, &err);
    if (!tox) { printf("ERR new %d\n", err); return 1; }
    tox_callback_self_connection_status(tox, on_self);
    tox_callback_friend_request(tox, on_request);
    tox_callback_friend_connection_status(tox, on_conn);
    tox_callback_friend_message(tox, on_msg);
    tox_callback_friend_read_receipt(tox, on_receipt);
    tox_callback_friend_name(tox, on_name);
    tox_callback_friend_status_message(tox, on_statusmsg);
    tox_callback_file_recv(tox, on_file_recv);
    tox_callback_file_recv_chunk(tox, on_file_chunk);
    tox_callback_file_chunk_request(tox, on_chunk_request);
    tox_callback_file_recv_control(tox, on_file_control);

    uint8_t addr[TOX_ADDRESS_SIZE], dht[32];
    tox_self_get_address(tox, addr);
    tox_self_get_dht_id(tox, dht);
    char ha[2 * TOX_ADDRESS_SIZE + 1], hd[65];
    hex(addr, TOX_ADDRESS_SIZE, ha); hex(dht, 32, hd);
    printf("READY %s %s %u\n", ha, hd, tox_self_get_udp_port(tox, NULL));
    fflush(stdout);

    char line[4096];
    for (;;) {
        tox_iterate(tox, NULL);
        fd_set fds; FD_ZERO(&fds); FD_SET(0, &fds);
        struct timeval tv = {0, tox_iteration_interval(tox) * 1000};
        if (select(1, &fds, NULL, NULL, &tv) > 0) {
            if (!fgets(line, sizeof line, stdin)) break;
            line[strcspn(line, "\r\n")] = 0;
            char *cmd = strtok(line, " ");
            if (!cmd) continue;
            if (!strcmp(cmd, "QUIT")) break;
            if (!strcmp(cmd, "BOOTSTRAP")) {
                char *ip = strtok(NULL, " "); int p = atoi(strtok(NULL, " ")); char *k = strtok(NULL, " ");
                uint8_t key[32]; unhex(k, key, 32);
                Tox_Err_Bootstrap e; tox_bootstrap(tox, ip, p, key, &e);
                if (e) { printf("ERR bootstrap %d\n", e); fflush(stdout); }
            } else if (!strcmp(cmd, "ADD")) {
                char *id = strtok(NULL, " "); char *msg = strtok(NULL, "");
                uint8_t a[TOX_ADDRESS_SIZE]; unhex(id, a, TOX_ADDRESS_SIZE);
                Tox_Err_Friend_Add e; uint32_t f = tox_friend_add(tox, a, (uint8_t *)msg, strlen(msg), &e);
                printf("ADDED %u %d\n", f, e); fflush(stdout);
            } else if (!strcmp(cmd, "ACCEPT")) {
                char *k = strtok(NULL, " "); uint8_t key[32]; unhex(k, key, 32);
                Tox_Err_Friend_Add e; uint32_t f = tox_friend_add_norequest(tox, key, &e);
                printf("ADDED %u %d\n", f, e); fflush(stdout);
            } else if (!strcmp(cmd, "MSG")) {
                uint32_t f = (uint32_t)atoi(strtok(NULL, " ")); char *msg = strtok(NULL, "");
                Tox_Err_Friend_Send_Message e;
                uint32_t id = tox_friend_send_message(tox, f, TOX_MESSAGE_TYPE_NORMAL, (uint8_t *)msg, strlen(msg), &e);
                printf("SENT %u %d\n", id, e); fflush(stdout);
            } else if (!strcmp(cmd, "NAME")) {
                char *n = strtok(NULL, ""); tox_self_set_name(tox, (uint8_t *)n, strlen(n), NULL);
            } else if (!strcmp(cmd, "STATUSMSG")) {
                char *n = strtok(NULL, ""); tox_self_set_status_message(tox, (uint8_t *)n, strlen(n), NULL);
            } else if (!strcmp(cmd, "SAVE")) {
                char *file = strtok(NULL, " ");
                size_t n = tox_get_savedata_size(tox); uint8_t *d = malloc(n); tox_get_savedata(tox, d);
                FILE *f = fopen(file, "wb"); fwrite(d, 1, n, f); fclose(f); free(d);
                printf("SAVED %zu\n", n); fflush(stdout);
            } else if (!strcmp(cmd, "FILESEND")) {
                uint32_t f = (uint32_t)atoi(strtok(NULL, " "));
                send_size = strtoull(strtok(NULL, " "), NULL, 10);
                char *name = strtok(NULL, "");
                Tox_Err_File_Send e;
                uint32_t file = tox_file_send(tox, f, TOX_FILE_KIND_DATA, send_size, NULL, (uint8_t *)name, strlen(name), &e);
                printf("FILESENDING %u %u %d\n", f, file, e); fflush(stdout);
            } else if (!strcmp(cmd, "SAVEENC")) {
                char *file = strtok(NULL, " "); char *pass = strtok(NULL, "");
                size_t n = tox_get_savedata_size(tox); uint8_t *d = malloc(n); tox_get_savedata(tox, d);
                uint8_t *e = malloc(n + TOX_PASS_ENCRYPTION_EXTRA_LENGTH);
                Tox_Err_Encryption ee;
                tox_pass_encrypt(d, n, (const uint8_t *)pass, strlen(pass), e, &ee);
                FILE *f = fopen(file, "wb"); fwrite(e, 1, n + TOX_PASS_ENCRYPTION_EXTRA_LENGTH, f); fclose(f);
                printf("SAVED %zu %d\n", n, ee); fflush(stdout);
            }
        }
    }
    tox_kill(tox);
    return 0;
}
