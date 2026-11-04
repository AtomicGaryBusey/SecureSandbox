#define _DARWIN_C_SOURCE
#include <CommonCrypto/CommonDigest.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/*
 * Exact signed bridge between the per-user credential helper and the
 * root-owned native-session controller. Credential bytes arrive only on the
 * helper-created pipe (stdin), and leave only on the separately passed
 * Research stream fd. The root controller receives digests, never the token.
 */

#define HELPER_MAGIC "SSHPRJ1\n"
#define CLAIM_MAGIC "SSCLM01\n"
#define FD_MAGIC "SSFD001\n"
#define READY_MAGIC "SSRDY01\n"
#define CODEX_MAGIC "SSCODX1\n"
#define TERMINAL_MAGIC "SSEND01\n"
#define MAGIC_BYTES 8U
#define UUID_BYTES 36U
#define SHA256_BYTES 64U
#define HELPER_HEADER_BYTES \
    (MAGIC_BYTES + UUID_BYTES + SHA256_BYTES + SHA256_BYTES + 8U + 4U)
#define CLAIM_BYTES \
    (MAGIC_BYTES + UUID_BYTES + SHA256_BYTES + SHA256_BYTES + SHA256_BYTES + 8U)
#define READY_BYTES (MAGIC_BYTES + UUID_BYTES + SHA256_BYTES)
#define TERMINAL_BYTES (MAGIC_BYTES + UUID_BYTES + SHA256_BYTES)
#define MIN_TOKEN_BYTES 16U
#define MAX_TOKEN_BYTES 65536U
#define HANDSHAKE_TIMEOUT_MS 120000

static void secure_zero(void *pointer, size_t size) {
    volatile uint8_t *bytes = (volatile uint8_t *)pointer;
    while (size-- > 0U) *bytes++ = 0U;
}

static uint64_t host_uint64_from_big_endian(uint64_t value) {
    const uint16_t marker = 1U;
    if (*(const uint8_t *)&marker == 0U) return value;
    return ((value & UINT64_C(0x00000000000000ff)) << 56U)
        | ((value & UINT64_C(0x000000000000ff00)) << 40U)
        | ((value & UINT64_C(0x0000000000ff0000)) << 24U)
        | ((value & UINT64_C(0x00000000ff000000)) << 8U)
        | ((value & UINT64_C(0x000000ff00000000)) >> 8U)
        | ((value & UINT64_C(0x0000ff0000000000)) >> 24U)
        | ((value & UINT64_C(0x00ff000000000000)) >> 40U)
        | ((value & UINT64_C(0xff00000000000000)) >> 56U);
}

static int wait_readable(int descriptor, int timeout_ms) {
    struct pollfd item = {.fd = descriptor, .events = POLLIN | POLLHUP};
    int result;
    do {
        result = poll(&item, 1, timeout_ms);
    } while (result < 0 && errno == EINTR);
    return result > 0 && (item.revents & (POLLIN | POLLHUP)) != 0 ? 0 : -1;
}

static int read_exact(int descriptor, void *buffer, size_t size) {
    uint8_t *cursor = buffer;
    while (size > 0U) {
        if (wait_readable(descriptor, HANDSHAKE_TIMEOUT_MS) != 0) return -1;
        ssize_t count = read(descriptor, cursor, size);
        if (count == 0) return -1;
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        cursor += (size_t)count;
        size -= (size_t)count;
    }
    return 0;
}

static int read_exact_blocking(int descriptor, void *buffer, size_t size) {
    uint8_t *cursor = buffer;
    while (size > 0U) {
        ssize_t count = read(descriptor, cursor, size);
        if (count == 0) return -1;
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        cursor += (size_t)count;
        size -= (size_t)count;
    }
    return 0;
}

static int write_exact(int descriptor, const void *buffer, size_t size) {
    const uint8_t *cursor = buffer;
    while (size > 0U) {
        ssize_t count = write(descriptor, cursor, size);
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (count == 0) return -1;
        cursor += (size_t)count;
        size -= (size_t)count;
    }
    return 0;
}

static int is_uuid4(const uint8_t *value) {
    for (size_t index = 0; index < UUID_BYTES; ++index) {
        uint8_t byte = value[index];
        if (index == 8U || index == 13U || index == 18U || index == 23U) {
            if (byte != '-') return 0;
        } else if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f'))) {
            return 0;
        }
    }
    return value[14] == '4' && strchr("89ab", value[19]) != NULL;
}

static int is_sha256(const uint8_t *value) {
    for (size_t index = 0; index < SHA256_BYTES; ++index) {
        uint8_t byte = value[index];
        if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static void digest_hex(const uint8_t digest[CC_SHA256_DIGEST_LENGTH], uint8_t output[65]) {
    static const char alphabet[] = "0123456789abcdef";
    for (size_t index = 0; index < CC_SHA256_DIGEST_LENGTH; ++index) {
        output[index * 2U] = (uint8_t)alphabet[digest[index] >> 4U];
        output[index * 2U + 1U] = (uint8_t)alphabet[digest[index] & 0x0fU];
    }
    output[64] = 0;
}

static int exact_local_socket(int descriptor, int require_root_peer) {
    struct stat information;
    struct sockaddr_storage local_address;
    struct sockaddr_storage peer_address;
    socklen_t local_address_size = sizeof(local_address);
    socklen_t peer_address_size = sizeof(peer_address);
    int socket_type = 0;
    socklen_t socket_type_size = sizeof(socket_type);
    uid_t peer_uid = (uid_t)-1;
    gid_t peer_gid = (gid_t)-1;
    if (descriptor < 0 || fstat(descriptor, &information) != 0
            || !S_ISSOCK(information.st_mode) || isatty(descriptor)
            || getsockopt(descriptor, SOL_SOCKET, SO_TYPE,
                          &socket_type, &socket_type_size) != 0
            || socket_type_size != sizeof(socket_type) || socket_type != SOCK_STREAM
            || getsockname(descriptor, (struct sockaddr *)&local_address,
                           &local_address_size) != 0
            || local_address.ss_family != AF_UNIX
            || getpeername(descriptor, (struct sockaddr *)&peer_address,
                           &peer_address_size) != 0
            || peer_address.ss_family != AF_UNIX) {
        return -1;
    }
    if (require_root_peer
            && (getpeereid(descriptor, &peer_uid, &peer_gid) != 0
                || peer_uid != 0 || peer_gid != 0)) {
        return -1;
    }
    return 0;
}

static int receive_stream_fd(int control) {
    uint8_t payload[MAGIC_BYTES];
    uint8_t ancillary[CMSG_SPACE(sizeof(int))];
    struct iovec vector = {.iov_base = payload, .iov_len = sizeof(payload)};
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    memset(ancillary, 0, sizeof(ancillary));
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = ancillary;
    message.msg_controllen = sizeof(ancillary);
    if (wait_readable(control, HANDSHAKE_TIMEOUT_MS) != 0) return -1;
    ssize_t count;
    do {
        count = recvmsg(control, &message, MSG_WAITALL);
    } while (count < 0 && errno == EINTR);
    if (count != (ssize_t)sizeof(payload) || memcmp(payload, FD_MAGIC, MAGIC_BYTES) != 0
            || (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0) {
        return -1;
    }
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    if (header == NULL || header->cmsg_level != SOL_SOCKET
            || header->cmsg_type != SCM_RIGHTS
            || header->cmsg_len != CMSG_LEN(sizeof(int))
            || CMSG_NXTHDR(&message, header) != NULL) {
        return -1;
    }
    int descriptor = -1;
    memcpy(&descriptor, CMSG_DATA(header), sizeof(descriptor));
    uint8_t extra = 0;
    ssize_t extra_count = recv(control, &extra, 1, MSG_PEEK | MSG_DONTWAIT);
    if (extra_count > 0 || (extra_count < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
        if (descriptor >= 0) close(descriptor);
        return -1;
    }
    if (descriptor < 0 || fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0
            || exact_local_socket(descriptor, 0) != 0) {
        if (descriptor >= 0) close(descriptor);
        return -1;
    }
    return descriptor;
}

static int fail(const char *code) {
    (void)dprintf(STDERR_FILENO, "native_projection_consumer:%s\n", code);
    return 70;
}

int main(int argc, char **argv) {
    uint8_t header[HELPER_HEADER_BYTES];
    uint8_t claim[CLAIM_BYTES];
    uint8_t ready[READY_BYTES];
    uint8_t terminal[TERMINAL_BYTES];
    uint8_t expected_terminal[TERMINAL_BYTES];
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    uint8_t digest_text[65];
    uint8_t *token = NULL;
    int stream = -1;
    int result = 70;
    struct rlimit no_core = {.rlim_cur = 0, .rlim_max = 0};
    (void)argv;
    signal(SIGPIPE, SIG_IGN);
    if (argc != 1 || geteuid() == 0 || setrlimit(RLIMIT_CORE, &no_core) != 0
            || ptrace(PT_DENY_ATTACH, 0, NULL, 0) != 0
            || exact_local_socket(STDOUT_FILENO, 1) != 0
            || read_exact(STDIN_FILENO, header, sizeof(header)) != 0
            || memcmp(header, HELPER_MAGIC, MAGIC_BYTES) != 0
            || !is_uuid4(header + MAGIC_BYTES)
            || !is_sha256(header + MAGIC_BYTES + UUID_BYTES)
            || !is_sha256(header + MAGIC_BYTES + UUID_BYTES + SHA256_BYTES)) {
        return fail("authority_invalid");
    }
    uint64_t expiry_be = 0;
    uint32_t length_be = 0;
    memcpy(&expiry_be, header + HELPER_HEADER_BYTES - 12U, 8U);
    memcpy(&length_be, header + HELPER_HEADER_BYTES - 4U, 4U);
    uint64_t expiry_ms = host_uint64_from_big_endian(expiry_be);
    uint32_t token_length = ntohl(length_be);
    uint64_t now_ms = (uint64_t)time(NULL) * 1000U;
    if (expiry_ms <= now_ms || expiry_ms > now_ms + 60U * 60U * 1000U
            || token_length < MIN_TOKEN_BYTES || token_length > MAX_TOKEN_BYTES) {
        return fail("credential_lifetime_invalid");
    }
    token = calloc((size_t)token_length + 1U, 1U);
    if (token == NULL || mlock(token, token_length) != 0
            || read_exact(STDIN_FILENO, token, token_length) != 0) {
        result = fail("credential_read_failed");
        goto cleanup;
    }
    for (uint32_t index = 0; index < token_length; ++index) {
        if (token[index] < 0x21 || token[index] > 0x7e) {
            result = fail("credential_encoding_invalid");
            goto cleanup;
        }
    }
    uint8_t trailing = 0;
    ssize_t trailing_count;
    do {
        trailing_count = read(STDIN_FILENO, &trailing, 1);
    } while (trailing_count < 0 && errno == EINTR);
    if (trailing_count != 0) {
        result = fail("credential_trailing_data");
        goto cleanup;
    }
    CC_SHA256(token, token_length, digest);
    digest_hex(digest, digest_text);
    size_t offset = 0;
    memcpy(claim + offset, CLAIM_MAGIC, MAGIC_BYTES); offset += MAGIC_BYTES;
    memcpy(claim + offset, header + MAGIC_BYTES, UUID_BYTES); offset += UUID_BYTES;
    memcpy(claim + offset, header + MAGIC_BYTES + UUID_BYTES, SHA256_BYTES);
    offset += SHA256_BYTES;
    memcpy(claim + offset,
           header + MAGIC_BYTES + UUID_BYTES + SHA256_BYTES, SHA256_BYTES);
    offset += SHA256_BYTES;
    memcpy(claim + offset, digest_text, SHA256_BYTES); offset += SHA256_BYTES;
    memcpy(claim + offset, &expiry_be, 8U); offset += 8U;
    if (offset != CLAIM_BYTES || write_exact(STDOUT_FILENO, claim, sizeof(claim)) != 0) {
        result = fail("claim_write_failed");
        goto cleanup;
    }
    stream = receive_stream_fd(STDOUT_FILENO);
    if (stream < 0) {
        result = fail("research_stream_invalid");
        goto cleanup;
    }
    if (write_exact(stream, CODEX_MAGIC, MAGIC_BYTES) != 0
            || write_exact(stream, header + MAGIC_BYTES, UUID_BYTES) != 0
            || write_exact(stream, &length_be, 4U) != 0
            || write_exact(stream, token, token_length) != 0) {
        result = fail("credential_projection_failed");
        goto cleanup;
    }
    secure_zero(token, token_length);
    (void)munlock(token, token_length);
    free(token);
    token = NULL;
    close(stream);
    stream = -1;
    memcpy(ready, READY_MAGIC, MAGIC_BYTES);
    memcpy(ready + MAGIC_BYTES, header + MAGIC_BYTES, UUID_BYTES);
    memcpy(ready + MAGIC_BYTES + UUID_BYTES, digest_text, SHA256_BYTES);
    if (write_exact(STDOUT_FILENO, ready, sizeof(ready)) != 0) {
        result = fail("ready_write_failed");
        goto cleanup;
    }
    memcpy(expected_terminal, TERMINAL_MAGIC, MAGIC_BYTES);
    memcpy(expected_terminal + MAGIC_BYTES,
           header + MAGIC_BYTES, UUID_BYTES);
    memcpy(expected_terminal + MAGIC_BYTES + UUID_BYTES,
           header + MAGIC_BYTES + UUID_BYTES, SHA256_BYTES);
    secure_zero(header, sizeof(header));
    secure_zero(claim, sizeof(claim));
    secure_zero(digest, sizeof(digest));
    secure_zero(digest_text, sizeof(digest_text));
    /* Custody remains projected until the root controller proves its exact
       session and network closure, then half-closes this authenticated socket.
       Crash EOF without the bound terminal record is never success. */
    if (read_exact_blocking(
            STDOUT_FILENO, terminal, sizeof(terminal)) != 0
            || memcmp(terminal, expected_terminal, sizeof(terminal)) != 0) {
        result = fail("terminal_ack_invalid");
        goto cleanup;
    }
    do {
        trailing_count = read(STDOUT_FILENO, &trailing, 1);
    } while (trailing_count < 0 && errno == EINTR);
    result = trailing_count == 0 ? 0 : fail("control_trailing_data");

cleanup:
    if (stream >= 0) close(stream);
    if (token != NULL) {
        secure_zero(token, token_length);
        (void)munlock(token, token_length);
        free(token);
    }
    secure_zero(header, sizeof(header));
    secure_zero(claim, sizeof(claim));
    secure_zero(digest, sizeof(digest));
    secure_zero(digest_text, sizeof(digest_text));
    secure_zero(ready, sizeof(ready));
    secure_zero(terminal, sizeof(terminal));
    secure_zero(expected_terminal, sizeof(expected_terminal));
    return result;
}
