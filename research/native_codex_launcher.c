#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif

/*
 * Minimal credential projection launcher for the admitted Codex app-server.
 *
 * The root supervisor must first atomically claim one projection permit and
 * pass its sole read-only, root-owned, unlinked file description as fd 3.  The
 * canonical permit binds the launch descriptor, frame UUID, access-token
 * digest, expiry, and launcher uid/gid.  A linked or caller-opened permit is
 * rejected.  The supervisor closes all other copies immediately after spawn.
 *
 * The signed Host helper then writes exactly one binary frame to fd 5:
 *
 *   8 bytes  "SSCODX1\n"
 *  36 bytes  lowercase UUIDv4 projection identifier
 *   4 bytes  big-endian access-token length
 *   N bytes  printable non-whitespace access token
 *
 * The frame must be followed by EOF.  A private write-only pipe on fd 6
 * returns a fixed content-free token digest/length receipt to the first-party
 * driver and is closed before exec.  Codex app-server JSON-RPC uses fresh
 * pipes on stdin/stdout/stderr; it never inherits either credential channel.
 * No token is accepted through argv, ambient state, a file, or a shell.
 */

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#define FRAME_MAGIC "SSCODX1\n"
#define FRAME_MAGIC_BYTES 8U
#define UUID_BYTES 36U
#define FRAME_HEADER_BYTES (FRAME_MAGIC_BYTES + UUID_BYTES + 4U)
#define MIN_TOKEN_BYTES 16U
#define MAX_TOKEN_BYTES 65536U
#define MAX_DESCRIPTOR_BYTES 2048U
#define MAX_PERMIT_BYTES 2048U
#define MAX_PERMIT_LIFETIME_SECONDS 120U
#define PERMIT_CLOCK_SKEW_SECONDS 5U
#define ACCESS_PREFIX "ACCESS_TOKEN="
#define ACCESS_PREFIX_BYTES 13U
#define PROJECTION_PERMIT_FD 3
#define EXECUTABLE_FD 4
#define PROJECTION_FRAME_FD 5
#define TOKEN_RECEIPT_FD 6
#define LAUNCH_GATE_FD 7
#define TOKEN_RECEIPT_MAGIC "SSCDXR1\n"
#define TOKEN_RECEIPT_MAGIC_BYTES 8U
#define TOKEN_RECEIPT_BODY_BYTES \
    (8U + 36U + 36U + 64U + 64U + 64U + 4U + 8U + 8U + 8U + 64U + 64U)
#define TOKEN_RECEIPT_BYTES (TOKEN_RECEIPT_BODY_BYTES + 64U)
#define LAUNCH_GATE_MAGIC "SSCDXG1\n"
#define LAUNCH_GATE_MAGIC_BYTES 8U
#define LAUNCH_GATE_BYTES (LAUNCH_GATE_MAGIC_BYTES + 64U)
#define CODEX_PROXY "http://172.30.10.1:8643"
#ifdef SECURE_SANDBOX_LAUNCHER_TEST
#define PROJECTION_IO_TIMEOUT_MILLISECONDS 250
#else
#define PROJECTION_IO_TIMEOUT_MILLISECONDS 15000
#endif

#define AUTHORITY_PATH "/run/secure-sandbox/native-codex/launch.authority"
#define RELEASE_ROOT "/usr/local/libexec/secure-sandbox-harnesses/releases"
#define CODEX_POLICY_ROOT "/etc/secure-sandbox/native-codex-policy"
#define CODEX_CONFIG_NAME "config.toml"
#define CODEX_SKILLS_NAME "skills"
#define SESSION_STATE_ROOT "/run/secure-sandbox/native-codex/session-state"
#define WORKSPACE "/home/agent/research-workspace"

struct launch_descriptor {
    char runtime_authority_sha256[65];
    char session_id[37];
    char native_stack_binding_sha256[65];
    char harness_binding_sha256[65];
    char harness_generation_id[65];
    char harness_executable_sha256[65];
    char model_id[16];
    char reasoning_effort[8];
    char cyber_access_program[16];
    char descriptor_sha256[65];
};

struct projection_permit {
    char projection_id[37];
    char session_id[37];
    char runtime_authority_sha256[65];
    char harness_generation_id[65];
    char harness_executable_sha256[65];
    char model_id[16];
    char access_token_sha256[65];
    uint64_t issued_at_unix;
    uint64_t expires_at_unix;
    uid_t launcher_uid;
    gid_t launcher_gid;
    char permit_sha256[65];
};

struct sha256_context {
    uint8_t block[64];
    uint32_t state[8];
    uint64_t bytes;
    size_t used;
};

static const uint32_t sha256_k[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

static uint32_t rotate_right(uint32_t value, unsigned int bits) {
    return (value >> bits) | (value << (32U - bits));
}

static void sha256_transform(struct sha256_context *context) {
    uint32_t words[64];
    uint32_t a, b, c, d, e, f, g, h;
    size_t index;
    for (index = 0; index < 16; ++index) {
        const uint8_t *item = context->block + index * 4U;
        words[index] = ((uint32_t)item[0] << 24U)
            | ((uint32_t)item[1] << 16U)
            | ((uint32_t)item[2] << 8U)
            | (uint32_t)item[3];
    }
    for (index = 16; index < 64; ++index) {
        uint32_t x = words[index - 15U];
        uint32_t y = words[index - 2U];
        uint32_t small0 = rotate_right(x, 7U) ^ rotate_right(x, 18U) ^ (x >> 3U);
        uint32_t small1 = rotate_right(y, 17U) ^ rotate_right(y, 19U) ^ (y >> 10U);
        words[index] = words[index - 16U] + small0 + words[index - 7U] + small1;
    }
    a = context->state[0]; b = context->state[1];
    c = context->state[2]; d = context->state[3];
    e = context->state[4]; f = context->state[5];
    g = context->state[6]; h = context->state[7];
    for (index = 0; index < 64; ++index) {
        uint32_t big1 = rotate_right(e, 6U) ^ rotate_right(e, 11U) ^ rotate_right(e, 25U);
        uint32_t choose = (e & f) ^ ((~e) & g);
        uint32_t temporary1 = h + big1 + choose + sha256_k[index] + words[index];
        uint32_t big0 = rotate_right(a, 2U) ^ rotate_right(a, 13U) ^ rotate_right(a, 22U);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temporary2 = big0 + majority;
        h = g; g = f; f = e; e = d + temporary1;
        d = c; c = b; b = a; a = temporary1 + temporary2;
    }
    context->state[0] += a; context->state[1] += b;
    context->state[2] += c; context->state[3] += d;
    context->state[4] += e; context->state[5] += f;
    context->state[6] += g; context->state[7] += h;
}

static void sha256_init(struct sha256_context *context) {
    memset(context, 0, sizeof(*context));
    context->state[0] = 0x6a09e667U; context->state[1] = 0xbb67ae85U;
    context->state[2] = 0x3c6ef372U; context->state[3] = 0xa54ff53aU;
    context->state[4] = 0x510e527fU; context->state[5] = 0x9b05688cU;
    context->state[6] = 0x1f83d9abU; context->state[7] = 0x5be0cd19U;
}

static void sha256_update(struct sha256_context *context, const uint8_t *data, size_t size) {
    context->bytes += size;
    while (size > 0U) {
        size_t room = 64U - context->used;
        size_t amount = size < room ? size : room;
        memcpy(context->block + context->used, data, amount);
        context->used += amount;
        data += amount;
        size -= amount;
        if (context->used == 64U) {
            sha256_transform(context);
            context->used = 0U;
        }
    }
}

static void sha256_final(struct sha256_context *context, uint8_t output[32]) {
    uint64_t bits = context->bytes * 8U;
    size_t index;
    context->block[context->used++] = 0x80U;
    if (context->used > 56U) {
        memset(context->block + context->used, 0, 64U - context->used);
        sha256_transform(context);
        context->used = 0U;
    }
    memset(context->block + context->used, 0, 56U - context->used);
    for (index = 0; index < 8U; ++index) {
        context->block[63U - index] = (uint8_t)(bits >> (index * 8U));
    }
    sha256_transform(context);
    for (index = 0; index < 8U; ++index) {
        output[index * 4U] = (uint8_t)(context->state[index] >> 24U);
        output[index * 4U + 1U] = (uint8_t)(context->state[index] >> 16U);
        output[index * 4U + 2U] = (uint8_t)(context->state[index] >> 8U);
        output[index * 4U + 3U] = (uint8_t)context->state[index];
    }
}

static void digest_hex(const uint8_t digest[32], char output[65]) {
    static const char alphabet[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < 32U; ++index) {
        output[index * 2U] = alphabet[digest[index] >> 4U];
        output[index * 2U + 1U] = alphabet[digest[index] & 0x0fU];
    }
    output[64] = '\0';
}

static int fixed_error(const char *code) {
    (void)dprintf(STDERR_FILENO, "native_codex_launcher:%s\n", code);
    return 70;
}

static void secure_zero(void *pointer, size_t size) {
    volatile uint8_t *bytes = (volatile uint8_t *)pointer;
    while (size-- > 0U) {
        *bytes++ = 0U;
    }
}

static int start_io_deadline(struct timespec *deadline) {
    uint64_t nanoseconds;
    if (clock_gettime(CLOCK_MONOTONIC, deadline) != 0) return -1;
    nanoseconds = (uint64_t)deadline->tv_nsec
        + (uint64_t)(PROJECTION_IO_TIMEOUT_MILLISECONDS % 1000) * UINT64_C(1000000);
    deadline->tv_sec += PROJECTION_IO_TIMEOUT_MILLISECONDS / 1000
        + (time_t)(nanoseconds / UINT64_C(1000000000));
    deadline->tv_nsec = (long)(nanoseconds % UINT64_C(1000000000));
    return 0;
}

static int wait_io(int descriptor, short events, const struct timespec *deadline) {
    struct pollfd item;
    struct timespec now;
    int milliseconds;
    int result;
    item.fd = descriptor;
    item.events = events;
    item.revents = 0;
    for (;;) {
        int64_t seconds;
        int64_t nanoseconds;
        int64_t remaining;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
        seconds = (int64_t)deadline->tv_sec - (int64_t)now.tv_sec;
        nanoseconds = (int64_t)deadline->tv_nsec - (int64_t)now.tv_nsec;
        remaining = seconds * INT64_C(1000000000) + nanoseconds;
        if (remaining <= 0) return -1;
        milliseconds = (int)((remaining + INT64_C(999999)) / INT64_C(1000000));
        result = poll(&item, 1U, milliseconds);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0 || (item.revents & (POLLERR | POLLNVAL)) != 0) return -1;
        if ((item.revents & (events | POLLHUP)) != 0) return 0;
    }
}

static int read_exact_deadline(
    int descriptor, void *buffer, size_t size, const struct timespec *deadline
) {
    uint8_t *cursor = (uint8_t *)buffer;
    while (size > 0U) {
        if (wait_io(descriptor, POLLIN, deadline) != 0) return -1;
        ssize_t received = read(descriptor, cursor, size);
        if (received == 0) {
            return -1;
        }
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        cursor += (size_t)received;
        size -= (size_t)received;
    }
    return 0;
}

static int read_exact(int descriptor, void *buffer, size_t size) {
    uint8_t *cursor = (uint8_t *)buffer;
    while (size > 0U) {
        ssize_t received = read(descriptor, cursor, size);
        if (received == 0) return -1;
        if (received < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        cursor += (size_t)received;
        size -= (size_t)received;
    }
    return 0;
}

static int write_exact(
    int descriptor, const void *buffer, size_t size,
    const struct timespec *deadline
) {
    const uint8_t *cursor = (const uint8_t *)buffer;
    while (size > 0U) {
        if (wait_io(descriptor, POLLOUT, deadline) != 0) return -1;
        ssize_t written = write(descriptor, cursor, size);
        if (written < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (written == 0) return -1;
        cursor += (size_t)written;
        size -= (size_t)written;
    }
    return 0;
}

static int require_exact_eof(
    int descriptor, const struct timespec *deadline
) {
    uint8_t tail;
    for (;;) {
        ssize_t received;
        if (wait_io(descriptor, POLLIN, deadline) != 0) return -1;
        received = read(descriptor, &tail, 1U);
        if (received == 0) return 0;
        if (received < 0 && errno == EINTR) continue;
        return -1;
    }
}

static int require_projection_pipe(int descriptor) {
    struct stat information;
    int flags;
    errno = 0;
    if (isatty(descriptor) != 0
            || fstat(descriptor, &information) != 0
            || !S_ISFIFO(information.st_mode)) {
        return -1;
    }
    flags = fcntl(descriptor, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY) {
        return -1;
    }
    return 0;
}

static int require_receipt_pipe(int descriptor) {
    struct stat information;
    int flags;
    errno = 0;
    if (isatty(descriptor) != 0
            || fstat(descriptor, &information) != 0
            || !S_ISFIFO(information.st_mode)) {
        return -1;
    }
    flags = fcntl(descriptor, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_WRONLY) return -1;
    return 0;
}

static int require_appserver_stdio(void) {
    struct stat input;
    struct stat output;
    struct stat error;
    int input_flags;
    int output_flags;
    int error_flags;
    if (isatty(STDIN_FILENO) != 0 || isatty(STDOUT_FILENO) != 0
            || isatty(STDERR_FILENO) != 0
            || fstat(STDIN_FILENO, &input) != 0
            || fstat(STDOUT_FILENO, &output) != 0
            || fstat(STDERR_FILENO, &error) != 0
            || !S_ISFIFO(input.st_mode) || !S_ISFIFO(output.st_mode)
            || !S_ISFIFO(error.st_mode)
            || (input.st_dev == output.st_dev && input.st_ino == output.st_ino)
            || (input.st_dev == error.st_dev && input.st_ino == error.st_ino)
            || (output.st_dev == error.st_dev && output.st_ino == error.st_ino)) {
        return -1;
    }
    input_flags = fcntl(STDIN_FILENO, F_GETFL);
    output_flags = fcntl(STDOUT_FILENO, F_GETFL);
    error_flags = fcntl(STDERR_FILENO, F_GETFL);
    if (input_flags < 0 || output_flags < 0 || error_flags < 0
            || (input_flags & O_ACCMODE) != O_RDONLY
            || (output_flags & O_ACCMODE) != O_WRONLY
            || (error_flags & O_ACCMODE) != O_WRONLY) {
        return -1;
    }
    return 0;
}

static int is_sha256(const char *value) {
    size_t index;
    if (strlen(value) != 64U) {
        return 0;
    }
    for (index = 0; index < 64U; ++index) {
        if (!((value[index] >= '0' && value[index] <= '9')
                || (value[index] >= 'a' && value[index] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int is_uuid4(const char *value) {
    size_t index;
    if (strlen(value) != UUID_BYTES) {
        return 0;
    }
    for (index = 0; index < UUID_BYTES; ++index) {
        if (index == 8U || index == 13U || index == 18U || index == 23U) {
            if (value[index] != '-') return 0;
        } else if (!((value[index] >= '0' && value[index] <= '9')
                || (value[index] >= 'a' && value[index] <= 'f'))) {
            return 0;
        }
    }
    return value[14] == '4'
        && (value[19] == '8' || value[19] == '9'
            || value[19] == 'a' || value[19] == 'b');
}

static int copy_line_value(
    char **cursor,
    const char *end,
    const char *name,
    char *output,
    size_t capacity
) {
    size_t name_length = strlen(name);
    char *line_end;
    size_t value_length;
    if ((size_t)(end - *cursor) <= name_length + 1U
            || memcmp(*cursor, name, name_length) != 0
            || (*cursor)[name_length] != '=') {
        return -1;
    }
    line_end = memchr(*cursor, '\n', (size_t)(end - *cursor));
    if (line_end == NULL) {
        return -1;
    }
    value_length = (size_t)(line_end - (*cursor + name_length + 1U));
    if (value_length == 0U || value_length >= capacity) {
        return -1;
    }
    memcpy(output, *cursor + name_length + 1U, value_length);
    output[value_length] = '\0';
    *cursor = line_end + 1;
    return 0;
}

static int descriptor_digest(const struct launch_descriptor *descriptor, char output[65]) {
    char canonical[1024];
    int length = snprintf(
        canonical,
        sizeof(canonical),
        "{\"cyber_access_program\":\"%s\","
        "\"harness_binding_sha256\":\"%s\","
        "\"harness_executable_sha256\":\"%s\","
        "\"harness_generation_id\":\"%s\","
        "\"model_id\":\"%s\","
        "\"native_stack_binding_sha256\":\"%s\","
        "\"reasoning_effort\":\"%s\","
        "\"runtime_authority_sha256\":\"%s\","
        "\"session_id\":\"%s\"}\n",
        descriptor->cyber_access_program,
        descriptor->harness_binding_sha256,
        descriptor->harness_executable_sha256,
        descriptor->harness_generation_id,
        descriptor->model_id,
        descriptor->native_stack_binding_sha256,
        descriptor->reasoning_effort,
        descriptor->runtime_authority_sha256,
        descriptor->session_id
    );
    struct sha256_context context;
    uint8_t digest[32];
    if (length <= 0 || (size_t)length >= sizeof(canonical)) {
        return -1;
    }
    sha256_init(&context);
    sha256_update(&context, (const uint8_t *)canonical, (size_t)length);
    sha256_final(&context, digest);
    digest_hex(digest, output);
    secure_zero(digest, sizeof(digest));
    secure_zero(&context, sizeof(context));
    secure_zero(canonical, sizeof(canonical));
    return 0;
}

static int load_descriptor(
    const char *path,
    uid_t expected_uid,
    gid_t expected_gid,
    struct launch_descriptor *descriptor
) {
    int file = -1;
    struct stat information;
    char raw[MAX_DESCRIPTOR_BYTES + 1U];
    ssize_t received;
    char *cursor;
    const char *end;
    char schema[64];
    char observed_digest[65];
    memset(descriptor, 0, sizeof(*descriptor));
    file = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (file < 0 || fstat(file, &information) != 0
            || !S_ISREG(information.st_mode) || information.st_nlink != 1
            || information.st_uid != expected_uid || information.st_gid != expected_gid
            || (information.st_mode & 0777U) != 0640U
            || information.st_size <= 0
            || (uint64_t)information.st_size > MAX_DESCRIPTOR_BYTES) {
        if (file >= 0) close(file);
        return -1;
    }
    received = read(file, raw, (size_t)information.st_size + 1U);
    if (received != information.st_size || close(file) != 0
            || raw[received - 1] != '\n'
            || memchr(raw, '\0', (size_t)received) != NULL) {
        return -1;
    }
    raw[received] = '\0';
    cursor = raw;
    end = raw + received;
    if (copy_line_value(&cursor, end, "schema", schema, sizeof(schema)) != 0
            || strcmp(schema, "secure-sandbox-native-codex-launch-v2") != 0
            || copy_line_value(&cursor, end, "runtime_authority_sha256",
                descriptor->runtime_authority_sha256,
                sizeof(descriptor->runtime_authority_sha256)) != 0
            || copy_line_value(&cursor, end, "session_id",
                descriptor->session_id,
                sizeof(descriptor->session_id)) != 0
            || copy_line_value(&cursor, end, "native_stack_binding_sha256",
                descriptor->native_stack_binding_sha256,
                sizeof(descriptor->native_stack_binding_sha256)) != 0
            || copy_line_value(&cursor, end, "harness_binding_sha256",
                descriptor->harness_binding_sha256,
                sizeof(descriptor->harness_binding_sha256)) != 0
            || copy_line_value(&cursor, end, "harness_generation_id",
                descriptor->harness_generation_id,
                sizeof(descriptor->harness_generation_id)) != 0
            || copy_line_value(&cursor, end, "harness_executable_sha256",
                descriptor->harness_executable_sha256,
                sizeof(descriptor->harness_executable_sha256)) != 0
            || copy_line_value(&cursor, end, "model_id", descriptor->model_id,
                sizeof(descriptor->model_id)) != 0
            || copy_line_value(&cursor, end, "reasoning_effort",
                descriptor->reasoning_effort,
                sizeof(descriptor->reasoning_effort)) != 0
            || copy_line_value(&cursor, end, "cyber_access_program",
                descriptor->cyber_access_program,
                sizeof(descriptor->cyber_access_program)) != 0
            || copy_line_value(&cursor, end, "descriptor_sha256",
                descriptor->descriptor_sha256,
                sizeof(descriptor->descriptor_sha256)) != 0
            || cursor != end) {
        secure_zero(raw, sizeof(raw));
        return -1;
    }
    if (!is_sha256(descriptor->runtime_authority_sha256)
            || !is_uuid4(descriptor->session_id)
            || !is_sha256(descriptor->native_stack_binding_sha256)
            || !is_sha256(descriptor->harness_binding_sha256)
            || !is_sha256(descriptor->harness_generation_id)
            || !is_sha256(descriptor->harness_executable_sha256)
            || !is_sha256(descriptor->descriptor_sha256)
            || (strcmp(descriptor->model_id, "gpt-6-sol") != 0
                && strcmp(descriptor->model_id, "gpt-6-luna") != 0
                && strcmp(descriptor->model_id, "gpt-6.1-sol") != 0)
            || (strcmp(descriptor->reasoning_effort, "low") != 0
                && strcmp(descriptor->reasoning_effort, "medium") != 0
                && strcmp(descriptor->reasoning_effort, "high") != 0
                && strcmp(descriptor->reasoning_effort, "xhigh") != 0)
            || strcmp(descriptor->cyber_access_program, "daybreakBlue") != 0
            || descriptor_digest(descriptor, observed_digest) != 0
            || strcmp(observed_digest, descriptor->descriptor_sha256) != 0) {
        secure_zero(raw, sizeof(raw));
        secure_zero(observed_digest, sizeof(observed_digest));
        return -1;
    }
    secure_zero(raw, sizeof(raw));
    secure_zero(observed_digest, sizeof(observed_digest));
    return 0;
}

static int parse_frame_header(
    int descriptor, char projection_id[37], uint32_t *token_length,
    const struct timespec *deadline
) {
    uint8_t header[FRAME_HEADER_BYTES];
    uint32_t network_length;
    if (require_projection_pipe(descriptor) != 0
            || read_exact_deadline(
                descriptor, header, sizeof(header), deadline) != 0
            || memcmp(header, FRAME_MAGIC, FRAME_MAGIC_BYTES) != 0) {
        secure_zero(header, sizeof(header));
        return -1;
    }
    memcpy(projection_id, header + FRAME_MAGIC_BYTES, UUID_BYTES);
    projection_id[UUID_BYTES] = '\0';
    memcpy(&network_length, header + FRAME_MAGIC_BYTES + UUID_BYTES, 4U);
    *token_length = ntohl(network_length);
    secure_zero(header, sizeof(header));
    if (!is_uuid4(projection_id)
            || *token_length < MIN_TOKEN_BYTES
            || *token_length > MAX_TOKEN_BYTES) {
        return -1;
    }
    return 0;
}

static int parse_uint64_canonical(const char *value, uint64_t *output) {
    uint64_t result = 0U;
    const unsigned char *cursor = (const unsigned char *)value;
    if (*cursor == '\0' || (*cursor == '0' && cursor[1] != '\0')) return -1;
    while (*cursor != '\0') {
        uint64_t digit;
        if (*cursor < '0' || *cursor > '9') return -1;
        digit = (uint64_t)(*cursor - '0');
        if (result > (UINT64_MAX - digit) / 10U) return -1;
        result = result * 10U + digit;
        ++cursor;
    }
    *output = result;
    return 0;
}

static void sha256_bytes(const void *bytes, size_t size, char output[65]) {
    struct sha256_context context;
    uint8_t digest[32];
    sha256_init(&context);
    sha256_update(&context, (const uint8_t *)bytes, size);
    sha256_final(&context, digest);
    digest_hex(digest, output);
    secure_zero(digest, sizeof(digest));
    secure_zero(&context, sizeof(context));
}

static uint64_t token_rolling_fingerprint(
    const uint8_t *token, uint32_t token_length
) {
    uint64_t result = 0U;
    uint32_t index;
    for (index = 0U; index < token_length; ++index) {
        result = result * UINT64_C(257) + (uint64_t)token[index];
    }
    return result;
}

static void encode_uint64(uint64_t value, uint8_t output[8]) {
    size_t index;
    for (index = 0U; index < 8U; ++index) {
        output[7U - index] = (uint8_t)(value >> (index * 8U));
    }
}

static int self_process_start_time(uint64_t *output) {
#ifdef __linux__
    int descriptor = -1;
    char raw[4096];
    ssize_t count;
    char *cursor;
    char *end;
    unsigned int field;
    uint64_t value = 0U;
    descriptor = open("/proc/self/stat", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) return -1;
    count = read(descriptor, raw, sizeof(raw) - 1U);
    if (count <= 0 || (size_t)count >= sizeof(raw) - 1U
            || read(descriptor, raw + count, 1U) != 0
            || close(descriptor) != 0) {
        if (descriptor >= 0) close(descriptor);
        secure_zero(raw, sizeof(raw));
        return -1;
    }
    descriptor = -1;
    raw[count] = '\0';
    cursor = strrchr(raw, ')');
    if (cursor == NULL || cursor[1] != ' ' || cursor[2] == '\0') goto rejected;
    cursor += 2;
    for (field = 0U; field <= 19U; ++field) {
        while (*cursor == ' ') ++cursor;
        if (*cursor == '\0') goto rejected;
        end = cursor;
        while (*end != '\0' && *end != ' ' && *end != '\n') ++end;
        if (field == 19U) {
            char saved = *end;
            *end = '\0';
            if (parse_uint64_canonical(cursor, &value) != 0 || value == 0U) {
                *end = saved;
                goto rejected;
            }
            *end = saved;
        }
        cursor = end;
    }
    secure_zero(raw, sizeof(raw));
    *output = value;
    return 0;
rejected:
    secure_zero(raw, sizeof(raw));
    return -1;
#else
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0) return -1;
    *output = (uint64_t)now.tv_sec * UINT64_C(1000000000)
        + (uint64_t)now.tv_nsec;
    return *output == 0U ? -1 : 0;
#endif
}

static int environment_proof(
    char *const environment[], const char token_digest[65], char output[65]
) {
    struct sha256_context context;
    uint8_t digest[32];
    static const char prefix[] = "ACCESS_TOKEN_SHA256=";
    size_t index;
    if (!is_sha256(token_digest) || environment == NULL
            || environment[0] == NULL) return -1;
    sha256_init(&context);
    sha256_update(&context, (const uint8_t *)prefix, sizeof(prefix) - 1U);
    sha256_update(&context, (const uint8_t *)token_digest, 64U);
    sha256_update(&context, (const uint8_t *)"\n", 1U);
    for (index = 1U; environment[index] != NULL; ++index) {
        size_t length = strlen(environment[index]);
        if (index > 11U || length == 0U || length > 511U
                || strncmp(environment[index], "ACCESS_TOKEN=", 13U) == 0
                || strncmp(environment[index], "NO_PROXY=", 9U) == 0
                || strncmp(environment[index], "ALL_PROXY=", 10U) == 0) {
            secure_zero(&context, sizeof(context));
            return -1;
        }
        sha256_update(
            &context, (const uint8_t *)environment[index], length);
        sha256_update(&context, (const uint8_t *)"\n", 1U);
    }
    if (index != 12U) {
        secure_zero(&context, sizeof(context));
        return -1;
    }
    sha256_final(&context, digest);
    digest_hex(digest, output);
    secure_zero(digest, sizeof(digest));
    secure_zero(&context, sizeof(context));
    return 0;
}

static int emit_token_receipt(
    int descriptor,
    const struct launch_descriptor *launch,
    const struct projection_permit *permit,
    const uint8_t *token,
    uint32_t token_length,
    char *const environment[],
    const char *codex_home,
    const struct timespec *deadline,
    char emitted_receipt_sha256[65]
) {
    uint8_t receipt[TOKEN_RECEIPT_BYTES];
    uint8_t *cursor = receipt;
    uint32_t network_length = htonl(token_length);
    uint64_t rolling_fingerprint;
    uint8_t rolling_bytes[8];
    uint8_t process_id_bytes[8];
    uint8_t process_start_bytes[8];
    char receipt_digest[65];
    char codex_home_digest[65];
    char environment_digest[65];
    uint64_t process_id = (uint64_t)getpid();
    uint64_t process_start = 0U;
    int result = -1;
    if (require_receipt_pipe(descriptor) != 0
            || strcmp(launch->session_id, permit->session_id) != 0
            || strcmp(launch->runtime_authority_sha256,
                permit->runtime_authority_sha256) != 0
            || token == NULL || token_length < MIN_TOKEN_BYTES
            || token_length > MAX_TOKEN_BYTES || codex_home == NULL
            || codex_home[0] != '/'
            || process_id <= 1U
            || self_process_start_time(&process_start) != 0
            || environment_proof(
                environment, permit->access_token_sha256,
                environment_digest) != 0) {
        goto done;
    }
    sha256_bytes(codex_home, strlen(codex_home), codex_home_digest);
    rolling_fingerprint = token_rolling_fingerprint(token, token_length);
    encode_uint64(rolling_fingerprint, rolling_bytes);
    encode_uint64(process_id, process_id_bytes);
    encode_uint64(process_start, process_start_bytes);
#define COPY_RECEIPT(value, length) do { \
    memcpy(cursor, (value), (length)); \
    cursor += (length); \
} while (0)
    COPY_RECEIPT(TOKEN_RECEIPT_MAGIC, TOKEN_RECEIPT_MAGIC_BYTES);
    COPY_RECEIPT(permit->projection_id, UUID_BYTES);
    COPY_RECEIPT(permit->session_id, UUID_BYTES);
    COPY_RECEIPT(permit->runtime_authority_sha256, 64U);
    COPY_RECEIPT(permit->permit_sha256, 64U);
    COPY_RECEIPT(permit->access_token_sha256, 64U);
    COPY_RECEIPT(&network_length, 4U);
    COPY_RECEIPT(rolling_bytes, sizeof(rolling_bytes));
    COPY_RECEIPT(process_id_bytes, sizeof(process_id_bytes));
    COPY_RECEIPT(process_start_bytes, sizeof(process_start_bytes));
    COPY_RECEIPT(codex_home_digest, 64U);
    COPY_RECEIPT(environment_digest, 64U);
#undef COPY_RECEIPT
    if ((size_t)(cursor - receipt) != TOKEN_RECEIPT_BODY_BYTES) goto done;
    sha256_bytes(receipt, TOKEN_RECEIPT_BODY_BYTES, receipt_digest);
    memcpy(cursor, receipt_digest, 64U);
    cursor += 64U;
    if ((size_t)(cursor - receipt) != TOKEN_RECEIPT_BYTES
            || write_exact(
                descriptor, receipt, sizeof(receipt), deadline) != 0) {
        goto done;
    }
    memcpy(emitted_receipt_sha256, receipt_digest, 65U);
    result = 0;
done:
    secure_zero(receipt_digest, sizeof(receipt_digest));
    secure_zero(rolling_bytes, sizeof(rolling_bytes));
    secure_zero(process_id_bytes, sizeof(process_id_bytes));
    secure_zero(process_start_bytes, sizeof(process_start_bytes));
    secure_zero(codex_home_digest, sizeof(codex_home_digest));
    secure_zero(environment_digest, sizeof(environment_digest));
    rolling_fingerprint = 0U;
    secure_zero(receipt, sizeof(receipt));
    return result;
}

static int wait_for_launch_gate(
    int descriptor, const char expected_receipt_sha256[65]
) {
    uint8_t frame[LAUNCH_GATE_BYTES];
    struct timespec deadline;
    int result = -1;
    if (require_projection_pipe(descriptor) != 0
            || !is_sha256(expected_receipt_sha256)
            || start_io_deadline(&deadline) != 0
            || read_exact_deadline(
                descriptor, frame, sizeof(frame), &deadline) != 0
            || require_exact_eof(descriptor, &deadline) != 0
            || memcmp(frame, LAUNCH_GATE_MAGIC,
                LAUNCH_GATE_MAGIC_BYTES) != 0
            || memcmp(frame + LAUNCH_GATE_MAGIC_BYTES,
                expected_receipt_sha256, 64U) != 0) {
        goto done;
    }
    result = 0;
done:
    secure_zero(frame, sizeof(frame));
    return result;
}

static int projection_permit_digest(
    const struct projection_permit *permit,
    char output[65]
) {
    char canonical[2048];
    int length = snprintf(
        canonical,
        sizeof(canonical),
        "{\"access_token_sha256\":\"%s\","
        "\"expires_at_unix\":%" PRIu64 ","
        "\"harness_executable_sha256\":\"%s\","
        "\"harness_generation_id\":\"%s\","
        "\"issued_at_unix\":%" PRIu64 ","
        "\"launcher_gid\":%" PRIu64 ","
        "\"launcher_uid\":%" PRIu64 ","
        "\"model_id\":\"%s\","
        "\"projection_id\":\"%s\","
        "\"runtime_authority_sha256\":\"%s\","
        "\"session_id\":\"%s\"}\n",
        permit->access_token_sha256,
        permit->expires_at_unix,
        permit->harness_executable_sha256,
        permit->harness_generation_id,
        permit->issued_at_unix,
        (uint64_t)permit->launcher_gid,
        (uint64_t)permit->launcher_uid,
        permit->model_id,
        permit->projection_id,
        permit->runtime_authority_sha256,
        permit->session_id
    );
    if (length <= 0 || (size_t)length >= sizeof(canonical)) return -1;
    sha256_bytes(canonical, (size_t)length, output);
    secure_zero(canonical, sizeof(canonical));
    return 0;
}

static int projection_permit_time_valid_at(
    const struct projection_permit *permit, uint64_t now
) {
    if (permit == NULL
            || permit->issued_at_unix >= permit->expires_at_unix
            || permit->expires_at_unix - permit->issued_at_unix
                > MAX_PERMIT_LIFETIME_SECONDS
            || (now < permit->issued_at_unix
                && permit->issued_at_unix - now > PERMIT_CLOCK_SKEW_SECONDS)
            || now >= permit->expires_at_unix) {
        return -1;
    }
    return 0;
}

static int projection_permit_time_valid(
    const struct projection_permit *permit
) {
    time_t now = time(NULL);
    if (now < 0) return -1;
    return projection_permit_time_valid_at(permit, (uint64_t)now);
}

static int load_projection_permit(
    int file,
    uid_t expected_file_uid,
    gid_t expected_file_gid,
    uid_t expected_launcher_uid,
    gid_t expected_launcher_gid,
    const struct launch_descriptor *descriptor,
    const char *projection_id,
    struct projection_permit *permit
) {
    struct stat information;
    char raw[MAX_PERMIT_BYTES + 1U];
    char schema[64];
    char issued[32], expires[32], uid_text[32], gid_text[32];
    char observed_digest[65];
    char *cursor;
    const char *end;
    uint8_t trailing;
    uint64_t uid_value, gid_value;
    size_t raw_size;
    int flags;
    memset(permit, 0, sizeof(*permit));
    flags = fcntl(file, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY
            || fstat(file, &information) != 0
            || !S_ISREG(information.st_mode) || information.st_nlink != 0
            || information.st_uid != expected_file_uid
            || information.st_gid != expected_file_gid
            || (information.st_mode & 07777U) != 0400U
            || information.st_size <= 0
            || (uint64_t)information.st_size > MAX_PERMIT_BYTES
            || lseek(file, 0, SEEK_CUR) != 0) {
        return -1;
    }
    raw_size = (size_t)information.st_size;
    if (read_exact(file, raw, raw_size) != 0 || read(file, &trailing, 1U) != 0
            || raw[raw_size - 1U] != '\n'
            || memchr(raw, '\0', raw_size) != NULL) {
        secure_zero(raw, sizeof(raw));
        return -1;
    }
    raw[raw_size] = '\0';
    cursor = raw;
    end = raw + raw_size;
    if (copy_line_value(&cursor, end, "schema", schema, sizeof(schema)) != 0
            || strcmp(schema, "secure-sandbox-native-codex-projection-permit-v1") != 0
            || copy_line_value(&cursor, end, "projection_id",
                permit->projection_id, sizeof(permit->projection_id)) != 0
            || copy_line_value(&cursor, end, "session_id",
                permit->session_id, sizeof(permit->session_id)) != 0
            || copy_line_value(&cursor, end, "runtime_authority_sha256",
                permit->runtime_authority_sha256,
                sizeof(permit->runtime_authority_sha256)) != 0
            || copy_line_value(&cursor, end, "harness_generation_id",
                permit->harness_generation_id,
                sizeof(permit->harness_generation_id)) != 0
            || copy_line_value(&cursor, end, "harness_executable_sha256",
                permit->harness_executable_sha256,
                sizeof(permit->harness_executable_sha256)) != 0
            || copy_line_value(&cursor, end, "model_id",
                permit->model_id, sizeof(permit->model_id)) != 0
            || copy_line_value(&cursor, end, "access_token_sha256",
                permit->access_token_sha256,
                sizeof(permit->access_token_sha256)) != 0
            || copy_line_value(&cursor, end, "issued_at_unix",
                issued, sizeof(issued)) != 0
            || copy_line_value(&cursor, end, "expires_at_unix",
                expires, sizeof(expires)) != 0
            || copy_line_value(&cursor, end, "launcher_uid",
                uid_text, sizeof(uid_text)) != 0
            || copy_line_value(&cursor, end, "launcher_gid",
                gid_text, sizeof(gid_text)) != 0
            || copy_line_value(&cursor, end, "permit_sha256",
                permit->permit_sha256, sizeof(permit->permit_sha256)) != 0
            || cursor != end
            || parse_uint64_canonical(issued, &permit->issued_at_unix) != 0
            || parse_uint64_canonical(expires, &permit->expires_at_unix) != 0
            || parse_uint64_canonical(uid_text, &uid_value) != 0
            || parse_uint64_canonical(gid_text, &gid_value) != 0
            || (uint64_t)(uid_t)uid_value != uid_value
            || (uint64_t)(gid_t)gid_value != gid_value) {
        secure_zero(raw, sizeof(raw));
        return -1;
    }
    permit->launcher_uid = (uid_t)uid_value;
    permit->launcher_gid = (gid_t)gid_value;
    if (!is_uuid4(permit->projection_id)
            || !is_uuid4(permit->session_id)
            || !is_sha256(permit->runtime_authority_sha256)
            || !is_sha256(permit->harness_generation_id)
            || !is_sha256(permit->harness_executable_sha256)
            || !is_sha256(permit->access_token_sha256)
            || !is_sha256(permit->permit_sha256)
            || (strcmp(permit->model_id, "gpt-6-sol") != 0
                && strcmp(permit->model_id, "gpt-6-luna") != 0
                && strcmp(permit->model_id, "gpt-6.1-sol") != 0)
            || strcmp(permit->projection_id, projection_id) != 0
            || strcmp(permit->session_id, descriptor->session_id) != 0
            || strcmp(permit->runtime_authority_sha256,
                descriptor->runtime_authority_sha256) != 0
            || strcmp(permit->harness_generation_id,
                descriptor->harness_generation_id) != 0
            || strcmp(permit->harness_executable_sha256,
                descriptor->harness_executable_sha256) != 0
            || strcmp(permit->model_id, descriptor->model_id) != 0
            || permit->launcher_uid != expected_launcher_uid
            || permit->launcher_gid != expected_launcher_gid
            || projection_permit_time_valid(permit) != 0
            || projection_permit_digest(permit, observed_digest) != 0
            || strcmp(observed_digest, permit->permit_sha256) != 0) {
        secure_zero(raw, sizeof(raw));
        secure_zero(observed_digest, sizeof(observed_digest));
        return -1;
    }
    secure_zero(raw, sizeof(raw));
    secure_zero(observed_digest, sizeof(observed_digest));
    return 0;
}

static int validate_token(const char *token, uint32_t size) {
    uint32_t index;
    for (index = 0U; index < size; ++index) {
        unsigned char byte = (unsigned char)token[index];
        if (byte < 0x21U || byte > 0x7eU) {
            return -1;
        }
    }
    return 0;
}

static void *locked_token_buffer(size_t token_size, size_t *mapping_size) {
    long page = sysconf(_SC_PAGESIZE);
    size_t needed = ACCESS_PREFIX_BYTES + token_size + 1U;
    void *mapping;
    if (page <= 0 || needed > SIZE_MAX - (size_t)page) {
        return MAP_FAILED;
    }
    *mapping_size = ((needed + (size_t)page - 1U) / (size_t)page) * (size_t)page;
    mapping = mmap(NULL, *mapping_size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED || mlock(mapping, *mapping_size) != 0) {
        if (mapping != MAP_FAILED) munmap(mapping, *mapping_size);
        return MAP_FAILED;
    }
#if defined(__linux__) && defined(MADV_DONTDUMP)
    if (madvise(mapping, *mapping_size, MADV_DONTDUMP) != 0) {
        secure_zero(mapping, *mapping_size);
        munlock(mapping, *mapping_size);
        munmap(mapping, *mapping_size);
        return MAP_FAILED;
    }
#endif
    return mapping;
}

static int close_via_proc(int keep, int keep_second, int keep_third) {
#ifdef __linux__
    DIR *stream = opendir("/proc/self/fd");
    struct dirent *entry;
    int iterator;
    if (stream == NULL) return 1;
    iterator = dirfd(stream);
    for (;;) {
        char *end = NULL;
        long descriptor;
        errno = 0;
        entry = readdir(stream);
        if (entry == NULL) {
            if (errno != 0 || closedir(stream) != 0) return -1;
            return 0;
        }
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
        errno = 0;
        descriptor = strtol(entry->d_name, &end, 10);
        if (errno != 0 || end == entry->d_name || *end != '\0'
                || descriptor < 3 || descriptor > INT_MAX
                || descriptor == keep || descriptor == keep_second
                || descriptor == keep_third
                || descriptor == iterator) {
            continue;
        }
        (void)close((int)descriptor);
        errno = 0;
        if (fcntl((int)descriptor, F_GETFD) >= 0 || errno != EBADF) {
            closedir(stream);
            return -1;
        }
    }
#else
    (void)keep;
    (void)keep_second;
    (void)keep_third;
    return 1;
#endif
}

static int close_by_scan(int keep, int keep_second, int keep_third) {
    struct rlimit limit;
    rlim_t descriptor;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0 || limit.rlim_cur == RLIM_INFINITY
            || limit.rlim_cur > (rlim_t)INT_MAX) {
        return -1;
    }
    for (descriptor = 3U; descriptor < limit.rlim_cur; ++descriptor) {
        int current = (int)descriptor;
        if (current == keep || current == keep_second
                || current == keep_third) continue;
        errno = 0;
        if (fcntl(current, F_GETFD) < 0 && errno == EBADF) continue;
        (void)close(current);
        errno = 0;
        if (fcntl(current, F_GETFD) >= 0 || errno != EBADF) return -1;
    }
    return 0;
}

static int close_all_except(int keep) {
#if defined(__linux__) && defined(SYS_close_range)
    int first_result = 0;
    int second_result = 0;
    int first_error = 0;
    int second_error = 0;
    if (keep < 3) {
        first_result = (int)syscall(SYS_close_range, 3U, UINT_MAX, 0U);
        if (first_result != 0) first_error = errno;
    } else if (keep > 3) {
        first_result = (int)syscall(SYS_close_range, 3U, (unsigned int)keep - 1U, 0U);
        if (first_result != 0) first_error = errno;
    }
    if (keep >= 3) {
        second_result = (int)syscall(
            SYS_close_range, (unsigned int)keep + 1U, UINT_MAX, 0U);
        if (second_result != 0) second_error = errno;
    }
    if (first_result == 0 && second_result == 0) return 0;
    if ((first_result != 0 && first_error != ENOSYS && first_error != EINVAL)
            || (second_result != 0 && second_error != ENOSYS
                && second_error != EINVAL)) {
        return -1;
    }
#endif
    {
        int proc_result = close_via_proc(keep, -1, -1);
        if (proc_result <= 0) return proc_result;
    }
    return close_by_scan(keep, -1, -1);
}

static int close_all_except_pair(int keep, int keep_second) {
    int proc_result;
    if (keep < 3 || keep_second < 3 || keep == keep_second) return -1;
    proc_result = close_via_proc(keep, keep_second, -1);
    if (proc_result <= 0) return proc_result;
    return close_by_scan(keep, keep_second, -1);
}

static int close_all_except_triple(int keep, int keep_second, int keep_third) {
    int proc_result;
    if (keep < 3 || keep_second < 3 || keep_third < 3
            || keep == keep_second || keep == keep_third
            || keep_second == keep_third) return -1;
    proc_result = close_via_proc(keep, keep_second, keep_third);
    if (proc_result <= 0) return proc_result;
    return close_by_scan(keep, keep_second, keep_third);
}

static int hash_open_file(int file, char output[65]) {
    struct sha256_context context;
    uint8_t digest[32];
    uint8_t buffer[65536];
    ssize_t received;
    if (lseek(file, 0, SEEK_SET) < 0) return -1;
    sha256_init(&context);
    while ((received = read(file, buffer, sizeof(buffer))) > 0) {
        sha256_update(&context, buffer, (size_t)received);
    }
    if (received < 0 || lseek(file, 0, SEEK_SET) < 0) {
        secure_zero(buffer, sizeof(buffer));
        secure_zero(&context, sizeof(context));
        return -1;
    }
    sha256_final(&context, digest);
    digest_hex(digest, output);
    secure_zero(buffer, sizeof(buffer));
    secure_zero(digest, sizeof(digest));
    secure_zero(&context, sizeof(context));
    return 0;
}

static int trusted_directory(int descriptor, uid_t owner, mode_t forbidden) {
    struct stat information;
    return fstat(descriptor, &information) == 0
        && S_ISDIR(information.st_mode)
        && information.st_uid == owner
        && (information.st_mode & forbidden) == 0;
}

static int open_admitted_executable(const struct launch_descriptor *descriptor) {
    int root = -1, generation = -1, executable = -1;
    struct stat before, after;
    char digest[65];
    root = open(RELEASE_ROOT, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0 || !trusted_directory(root, 0, 0022U)) goto rejected;
    generation = openat(root, descriptor->harness_generation_id,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (generation < 0 || !trusted_directory(generation, 0, 0022U)) goto rejected;
    executable = openat(generation, "harness", O_RDONLY | O_NOFOLLOW);
    if (executable < 0 || fstat(executable, &before) != 0
            || !S_ISREG(before.st_mode) || before.st_nlink != 1
            || before.st_uid != 0 || (before.st_mode & 0777U) != 0555U
            || before.st_size <= 0 || hash_open_file(executable, digest) != 0
            || fstat(executable, &after) != 0
            || before.st_dev != after.st_dev || before.st_ino != after.st_ino
            || before.st_size != after.st_size || before.st_mtime != after.st_mtime
            || before.st_ctime != after.st_ctime
            || strcmp(digest, descriptor->harness_executable_sha256) != 0) {
        goto rejected;
    }
    close(generation);
    close(root);
    secure_zero(digest, sizeof(digest));
    return executable;
rejected:
    if (executable >= 0) close(executable);
    if (generation >= 0) close(generation);
    if (root >= 0) close(root);
    secure_zero(digest, sizeof(digest));
    return -1;
}

static int immutable_policy_node(
    const struct stat *information,
    uid_t expected_uid,
    gid_t expected_gid,
    int directory
) {
    if (information->st_uid != expected_uid || information->st_gid != expected_gid
            || (information->st_mode & 0022U) != 0
            || (information->st_mode & 07000U) != 0) {
        return 0;
    }
    if (directory) return S_ISDIR(information->st_mode);
    return S_ISREG(information->st_mode) && information->st_nlink == 1;
}

static int validate_immutable_tree(
    int directory,
    uid_t expected_uid,
    gid_t expected_gid,
    unsigned int depth,
    size_t *node_count
) {
    int duplicate;
    DIR *stream;
    struct dirent *entry;
    if (depth > 16U || *node_count > 4096U) return -1;
    duplicate = dup(directory);
    if (duplicate < 0 || fcntl(duplicate, F_SETFD, FD_CLOEXEC) != 0) {
        if (duplicate >= 0) close(duplicate);
        return -1;
    }
    stream = fdopendir(duplicate);
    if (stream == NULL) {
        close(duplicate);
        return -1;
    }
    errno = 0;
    while ((entry = readdir(stream)) != NULL) {
        struct stat before, after;
        int child;
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (++(*node_count) > 4096U
                || fstatat(directory, entry->d_name, &before, AT_SYMLINK_NOFOLLOW) != 0) {
            closedir(stream);
            return -1;
        }
        if (S_ISDIR(before.st_mode)) {
            child = openat(directory, entry->d_name,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child < 0 || fstat(child, &after) != 0
                    || before.st_dev != after.st_dev || before.st_ino != after.st_ino
                    || !immutable_policy_node(&after, expected_uid, expected_gid, 1)
                    || validate_immutable_tree(
                        child, expected_uid, expected_gid,
                        depth + 1U, node_count) != 0) {
                if (child >= 0) close(child);
                closedir(stream);
                return -1;
            }
            close(child);
        } else if (S_ISREG(before.st_mode)) {
            child = openat(directory, entry->d_name,
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            if (child < 0 || fstat(child, &after) != 0
                    || before.st_dev != after.st_dev || before.st_ino != after.st_ino
                    || !immutable_policy_node(&after, expected_uid, expected_gid, 0)) {
                if (child >= 0) close(child);
                closedir(stream);
                return -1;
            }
            close(child);
        } else {
            closedir(stream);
            return -1;
        }
        errno = 0;
    }
    if (errno != 0 || closedir(stream) != 0) return -1;
    return 0;
}

static int require_codex_policy_at(
    const char *path,
    uid_t expected_uid,
    gid_t expected_gid
) {
    int root = -1, config = -1, skills = -1;
    struct stat information;
    size_t node_count = 0U;
    root = open(path,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0 || fstat(root, &information) != 0
            || !immutable_policy_node(
                &information, expected_uid, expected_gid, 1)
            || (information.st_mode & 0777U) != 0755U) goto rejected;
    config = openat(root, CODEX_CONFIG_NAME, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (config < 0 || fstat(config, &information) != 0
            || !immutable_policy_node(
                &information, expected_uid, expected_gid, 0)
            || (information.st_mode & 0777U) != 0444U
            || information.st_size <= 0 || information.st_size > 262144) goto rejected;
    skills = openat(root, CODEX_SKILLS_NAME,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (skills < 0 || fstat(skills, &information) != 0
            || !immutable_policy_node(
                &information, expected_uid, expected_gid, 1)
            || (information.st_mode & 0777U) != 0555U
            || validate_immutable_tree(
                root, expected_uid, expected_gid, 0U, &node_count) != 0) {
        goto rejected;
    }
    close(skills);
    close(config);
    close(root);
    return 0;
rejected:
    if (skills >= 0) close(skills);
    if (config >= 0) close(config);
    if (root >= 0) close(root);
    return -1;
}

static int require_codex_policy(void) {
    return require_codex_policy_at(CODEX_POLICY_ROOT, 0, 0);
}

static int directory_is_empty(int directory) {
    int duplicate = dup(directory);
    DIR *stream;
    struct dirent *entry;
    int result = 0;
    if (duplicate < 0 || fcntl(duplicate, F_SETFD, FD_CLOEXEC) != 0) {
        if (duplicate >= 0) close(duplicate);
        return 0;
    }
    stream = fdopendir(duplicate);
    if (stream == NULL) {
        close(duplicate);
        return 0;
    }
    errno = 0;
    while ((entry = readdir(stream)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            result = 0;
            goto done;
        }
    }
    result = errno == 0;
done:
    if (closedir(stream) != 0) result = 0;
    return result;
}

static int require_state_child(int session, const char *name, uid_t uid, gid_t gid) {
    int child = openat(session, name,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat information;
    int accepted = child >= 0 && fstat(child, &information) == 0
        && S_ISDIR(information.st_mode)
        && information.st_uid == uid && information.st_gid == gid
        && (information.st_mode & 07777U) == 0700U
        && directory_is_empty(child);
    if (child >= 0) close(child);
    return accepted ? 0 : -1;
}

static int require_regular_child(
    int parent,
    const char *name,
    uid_t uid,
    gid_t gid,
    mode_t mode,
    off_t minimum_size,
    off_t maximum_size
) {
    int child = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat information;
    int accepted = child >= 0 && fstat(child, &information) == 0
        && S_ISREG(information.st_mode) && information.st_nlink == 1
        && information.st_uid == uid && information.st_gid == gid
        && (information.st_mode & 07777U) == mode
        && information.st_size >= minimum_size
        && information.st_size <= maximum_size;
    if (child >= 0) close(child);
    return accepted ? 0 : -1;
}

static int regular_files_equal(int left_parent, int right_parent, const char *name) {
    int left = -1, right = -1;
    struct stat left_information, right_information;
    unsigned char left_bytes[4096], right_bytes[4096];
    ssize_t left_count, right_count;
    int result = -1;
    left = openat(left_parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    right = openat(right_parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (left < 0 || right < 0
            || fstat(left, &left_information) != 0
            || fstat(right, &right_information) != 0
            || !S_ISREG(left_information.st_mode)
            || !S_ISREG(right_information.st_mode)
            || left_information.st_size <= 0
            || left_information.st_size > 262144
            || left_information.st_size != right_information.st_size) {
        goto done;
    }
    do {
        left_count = read(left, left_bytes, sizeof(left_bytes));
        right_count = read(right, right_bytes, sizeof(right_bytes));
        if (left_count < 0 || right_count != left_count
                || (left_count > 0
                    && memcmp(left_bytes, right_bytes, (size_t)left_count) != 0)) {
            goto done;
        }
    } while (left_count > 0);
    result = 0;
done:
    secure_zero(left_bytes, sizeof(left_bytes));
    secure_zero(right_bytes, sizeof(right_bytes));
    if (right >= 0) close(right);
    if (left >= 0) close(left);
    return result;
}

static int codex_home_layout_is_exact(int directory) {
    int duplicate = dup(directory);
    DIR *stream;
    struct dirent *entry;
    unsigned int seen = 0U;
    int result = 0;
    if (duplicate < 0 || fcntl(duplicate, F_SETFD, FD_CLOEXEC) != 0) {
        if (duplicate >= 0) close(duplicate);
        return 0;
    }
    stream = fdopendir(duplicate);
    if (stream == NULL) {
        close(duplicate);
        return 0;
    }
    errno = 0;
    while ((entry = readdir(stream)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (strcmp(entry->d_name, CODEX_CONFIG_NAME) == 0) seen |= 1U;
        else if (strcmp(entry->d_name, CODEX_SKILLS_NAME) == 0) seen |= 2U;
        else if (strcmp(entry->d_name, "state") == 0) seen |= 4U;
        else if (strcmp(entry->d_name, "logs") == 0) seen |= 8U;
        else if (strcmp(entry->d_name, "tmp") == 0) seen |= 16U;
        else if (strcmp(entry->d_name, ".tmp") == 0) seen |= 32U;
        else if (strcmp(entry->d_name, "installation_id") == 0) seen |= 64U;
        else goto done;
        errno = 0;
    }
    result = errno == 0 && seen == 127U;
done:
    if (closedir(stream) != 0) result = 0;
    return result;
}

static int require_codex_home(
    int session,
    const char *policy_path,
    uid_t root_uid,
    uid_t launcher_uid,
    gid_t launcher_gid
) {
    int home = -1, policy = -1, skills = -1;
    struct stat information;
    home = openat(session, "codex-home",
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    policy = open(policy_path,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (home < 0 || policy < 0 || fstat(home, &information) != 0
            || !S_ISDIR(information.st_mode) || information.st_uid != root_uid
            || information.st_gid != launcher_gid
            || (information.st_mode & 07777U) != 0710U
            || !codex_home_layout_is_exact(home)
            || require_regular_child(home, CODEX_CONFIG_NAME,
                root_uid, launcher_gid, 0640U, 1, 262144) != 0
            || regular_files_equal(home, policy, CODEX_CONFIG_NAME) != 0
            || require_state_child(home, "state", launcher_uid, launcher_gid) != 0
            || require_state_child(home, "logs", launcher_uid, launcher_gid) != 0
            || require_state_child(home, "tmp", launcher_uid, launcher_gid) != 0
            || require_state_child(home, ".tmp", launcher_uid, launcher_gid) != 0
            || require_regular_child(home, "installation_id",
                launcher_uid, launcher_gid, 0600U, 36, 36) != 0) {
        goto rejected;
    }
    skills = openat(home, CODEX_SKILLS_NAME,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (skills < 0 || fstat(skills, &information) != 0
            || !S_ISDIR(information.st_mode) || information.st_uid != root_uid
            || information.st_gid != launcher_gid
            || (information.st_mode & 07777U) != 0750U
            || !directory_is_empty(skills)) {
        goto rejected;
    }
    close(skills);
    close(policy);
    close(home);
    return 0;
rejected:
    if (skills >= 0) close(skills);
    if (policy >= 0) close(policy);
    if (home >= 0) close(home);
    return -1;
}

static int session_layout_is_exact(int session) {
    int duplicate = dup(session);
    DIR *stream;
    struct dirent *entry;
    unsigned int seen = 0U;
    int result = 0;
    if (duplicate < 0 || fcntl(duplicate, F_SETFD, FD_CLOEXEC) != 0) {
        if (duplicate >= 0) close(duplicate);
        return 0;
    }
    stream = fdopendir(duplicate);
    if (stream == NULL) {
        close(duplicate);
        return 0;
    }
    errno = 0;
    while ((entry = readdir(stream)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (strcmp(entry->d_name, "home") == 0) seen |= 1U;
        else if (strcmp(entry->d_name, "cache") == 0) seen |= 2U;
        else if (strcmp(entry->d_name, "tmp") == 0) seen |= 4U;
        else if (strcmp(entry->d_name, "codex-home") == 0) seen |= 8U;
        else goto done;
        errno = 0;
    }
    result = errno == 0 && seen == 15U;
done:
    if (closedir(stream) != 0) result = 0;
    return result;
}

static int require_session_state_at(
    const char *root_path,
    const char *policy_path,
    const char *session_id,
    uid_t root_uid,
    uid_t launcher_uid,
    gid_t launcher_gid
) {
    int root = -1, session = -1;
    struct stat information;
    root = open(root_path,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0 || fstat(root, &information) != 0
            || !S_ISDIR(information.st_mode) || information.st_uid != root_uid
            || information.st_gid != launcher_gid
            || (information.st_mode & 07777U) != 0750U) goto rejected;
    session = openat(root, session_id,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (session < 0 || fstat(session, &information) != 0
            || !S_ISDIR(information.st_mode) || information.st_uid != root_uid
            || information.st_gid != launcher_gid
            || (information.st_mode & 07777U) != 0710U
            || !session_layout_is_exact(session)
            || require_state_child(
                session, "home", launcher_uid, launcher_gid) != 0
            || require_state_child(
                session, "cache", launcher_uid, launcher_gid) != 0
            || require_state_child(
                session, "tmp", launcher_uid, launcher_gid) != 0) {
        goto rejected;
    }
    if (require_codex_home(
            session, policy_path, root_uid, launcher_uid, launcher_gid) != 0) {
        goto rejected;
    }
    close(session);
    close(root);
    return 0;
rejected:
    if (session >= 0) close(session);
    if (root >= 0) close(root);
    return -1;
}

static int require_session_state(const char *session_id) {
    return require_session_state_at(
        SESSION_STATE_ROOT, CODEX_POLICY_ROOT,
        session_id, 0, geteuid(), getegid());
}

static int enter_workspace(void) {
    int directory = open(WORKSPACE, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0 || fchdir(directory) != 0) {
        if (directory >= 0) close(directory);
        return -1;
    }
    close(directory);
    return 0;
}

static int normalize_executable_descriptor(int executable) {
    int flags;
    if (executable != EXECUTABLE_FD) {
        if (dup2(executable, EXECUTABLE_FD) < 0 || close(executable) != 0) return -1;
    }
    flags = fcntl(EXECUTABLE_FD, F_GETFD);
    if (flags < 0 || fcntl(EXECUTABLE_FD, F_SETFD, flags & ~FD_CLOEXEC) != 0) {
        return -1;
    }
    return close_all_except(EXECUTABLE_FD);
}

static int harden_process(void) {
    struct rlimit no_core = {0, 0};
    umask(0077);
    if (setrlimit(RLIMIT_CORE, &no_core) != 0) return -1;
#ifdef __linux__
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
            || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
#endif
    return 0;
}

static int format_session_environment(
    char *output,
    size_t capacity,
    const char *name,
    const char *session_id,
    const char *leaf
) {
    int length = snprintf(output, capacity, "%s=%s/%s/%s",
        name, SESSION_STATE_ROOT, session_id, leaf);
    return length > 0 && (size_t)length < capacity ? 0 : -1;
}

static int format_session_config_option(
    char *output,
    size_t capacity,
    const char *name,
    const char *session_id,
    const char *leaf
) {
    int length = snprintf(output, capacity, "%s=\"%s/%s/codex-home/%s\"",
        name, SESSION_STATE_ROOT, session_id, leaf);
    return length > 0 && (size_t)length < capacity ? 0 : -1;
}

#ifndef SECURE_SANDBOX_LAUNCHER_TEST

int main(int argc, char **argv) {
    struct launch_descriptor descriptor;
    struct projection_permit permit;
    char projection_id[37];
    char token_digest[65];
    char token_receipt_digest[65];
    uint32_t token_length = 0U;
    struct timespec projection_deadline;
    int executable = -1;
    size_t mapping_size = 0U;
    char *access_environment = MAP_FAILED;
    char model_option[64];
    char reasoning_option[64];
    char home_environment[256];
    char cache_environment[256];
    char temporary_environment[256];
    char codex_home_environment[256];
    char codex_config_environment[256];
    char codex_sqlite_environment[256];
    char sqlite_option[256];
    char log_option[256];
    char *environment[] = {
        NULL,
        codex_home_environment,
        codex_config_environment,
        codex_sqlite_environment,
        home_environment,
        cache_environment,
        temporary_environment,
        "LANG=C.UTF-8",
        "LC_ALL=C.UTF-8",
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "HTTP_PROXY=" CODEX_PROXY,
        "HTTPS_PROXY=" CODEX_PROXY,
        NULL,
    };
    char *arguments[] = {
        "codex", "app-server", "--strict-config", "--listen", "stdio://",
        "-c", "model_provider=\"openai_chatgpt_plan\"",
        "-c", "model_providers.openai_chatgpt_plan.name=\"ChatGPT plan\"",
        "-c", "model_providers.openai_chatgpt_plan.base_url=\"https://api.openai.com/v1\"",
        "-c", "model_providers.openai_chatgpt_plan.env_key=\"ACCESS_TOKEN\"",
        "-c", "model_providers.openai_chatgpt_plan.wire_api=\"responses\"",
        "-c", "model_providers.openai_chatgpt_plan.requires_openai_auth=false",
        "-c", "model_providers.openai_chatgpt_plan.supports_websockets=false",
        "-c", "approval_policy=\"never\"",
        "-c", "approvals_reviewer=\"user\"",
        "-c", "sandbox_mode=\"workspace-write\"",
        "-c", "sandbox_workspace_write.network_access=false",
        "-c", "sandbox_workspace_write.exclude_tmpdir_env_var=true",
        "-c", "sandbox_workspace_write.exclude_slash_tmp=true",
        "-c", "suppress_unstable_features_warning=true",
        "-c", "shell_environment_policy.inherit=\"none\"",
        "-c", "shell_environment_policy.ignore_default_excludes=false",
        "-c", "shell_environment_policy.exclude=[\"ACCESS_TOKEN\",\"OPENAI_API_KEY\",\"OPENAI_ACCESS_TOKEN\",\"OPENAI_REFRESH_TOKEN\",\"CHATGPT_ACCESS_TOKEN\",\"CHATGPT_REFRESH_TOKEN\"]",
        "-c", "shell_environment_policy.set={}",
        "-c", "mcp_servers={}",
        "-c", "history.persistence=\"none\"",
        "-c", sqlite_option,
        "-c", log_option,
        "-c", "projects.\"/home/agent/research-workspace\".trust_level=\"untrusted\"",
        "-c", "skills.bundled.enabled=false",
        "-c", "skills.include_instructions=false",
        "-c", "project_doc_max_bytes=0",
        "-c", "project_doc_fallback_filenames=[]",
        "-c", "tools.web_search=false",
        "-c", "features.plugins=false",
        "-c", "features.remote_plugin=false",
        "-c", "features.plugin_discovery_prefetch=false",
        "-c", "features.plugin_sharing=false",
        "-c", "features.recommended_plugins=false",
        "-c", "features.apps=false",
        "-c", "features.enable_mcp_apps=false",
        "-c", "features.hooks=false",
        "-c", "features.multi_agent=false",
        "-c", "features.multi_agent_v2=false",
        "-c", "features.browser_use=false",
        "-c", "features.browser_use_external=false",
        "-c", "features.browser_use_full_cdp_access=false",
        "-c", "features.in_app_browser=false",
        "-c", "features.image_generation=false",
        "-c", "features.workspace_dependencies=false",
        "-c", "features.skill_search=false",
        "-c", "features.skill_catalog_deltas=false",
        "-c", "features.skill_mcp_dependency_install=false",
        "-c", "features.skip_host_skill_discovery=true",
        "-c", "daybreak=true",
        "-c", reasoning_option,
        "-c", model_option,
        NULL,
    };
    (void)argv;
    if (argc != 1 || harden_process() != 0
            || load_descriptor(AUTHORITY_PATH, 0, getegid(), &descriptor) != 0
            || require_codex_policy() != 0
            || require_session_state(descriptor.session_id) != 0
            || enter_workspace() != 0
            || format_session_environment(home_environment,
                sizeof(home_environment), "HOME", descriptor.session_id, "home") != 0
            || format_session_environment(cache_environment,
                sizeof(cache_environment), "XDG_CACHE_HOME",
                descriptor.session_id, "cache") != 0
            || format_session_environment(temporary_environment,
                sizeof(temporary_environment), "TMPDIR",
                descriptor.session_id, "tmp") != 0
            || format_session_environment(codex_home_environment,
                sizeof(codex_home_environment), "CODEX_HOME",
                descriptor.session_id, "codex-home") != 0
            || format_session_environment(codex_config_environment,
                sizeof(codex_config_environment), "XDG_CONFIG_HOME",
                descriptor.session_id, "codex-home") != 0
            || format_session_environment(codex_sqlite_environment,
                sizeof(codex_sqlite_environment), "CODEX_SQLITE_HOME",
                descriptor.session_id, "codex-home/state") != 0
            || format_session_config_option(sqlite_option,
                sizeof(sqlite_option), "sqlite_home",
                descriptor.session_id, "state") != 0
            || format_session_config_option(log_option,
                sizeof(log_option), "log_dir",
                descriptor.session_id, "logs") != 0) {
        return fixed_error("launch_authority_invalid");
    }
    if (start_io_deadline(&projection_deadline) != 0
            || parse_frame_header(
                PROJECTION_FRAME_FD, projection_id, &token_length,
                &projection_deadline) != 0) {
        return fixed_error("projection_frame_invalid");
    }
    if (load_projection_permit(
            PROJECTION_PERMIT_FD, 0, 0, geteuid(), getegid(),
            &descriptor, projection_id, &permit) != 0
            || close(PROJECTION_PERMIT_FD) != 0) {
        secure_zero(&permit, sizeof(permit));
        return fixed_error("projection_permit_invalid");
    }
    if (require_appserver_stdio() != 0
            || require_receipt_pipe(TOKEN_RECEIPT_FD) != 0
            || require_projection_pipe(LAUNCH_GATE_FD) != 0
            || close_all_except_triple(
                PROJECTION_FRAME_FD, TOKEN_RECEIPT_FD,
                LAUNCH_GATE_FD) != 0) {
        secure_zero(&permit, sizeof(permit));
        return fixed_error("descriptor_hygiene_failed");
    }
    executable = open_admitted_executable(&descriptor);
    if (executable < 0) {
        secure_zero(&permit, sizeof(permit));
        return fixed_error("harness_invalid");
    }
    access_environment = locked_token_buffer(token_length, &mapping_size);
    if (access_environment == MAP_FAILED) {
        secure_zero(&permit, sizeof(permit));
        close(executable);
        return fixed_error("credential_memory_unavailable");
    }
    memcpy(access_environment, ACCESS_PREFIX, ACCESS_PREFIX_BYTES);
    if (read_exact_deadline(PROJECTION_FRAME_FD,
            access_environment + ACCESS_PREFIX_BYTES, token_length,
            &projection_deadline) != 0
            || require_exact_eof(
                PROJECTION_FRAME_FD, &projection_deadline) != 0
            || close(PROJECTION_FRAME_FD) != 0
            || validate_token(access_environment + ACCESS_PREFIX_BYTES,
                token_length) != 0) {
        secure_zero(&permit, sizeof(permit));
        secure_zero(access_environment, mapping_size);
        munlock(access_environment, mapping_size);
        munmap(access_environment, mapping_size);
        close(executable);
        return fixed_error("credential_frame_invalid");
    }
    sha256_bytes(access_environment + ACCESS_PREFIX_BYTES, token_length, token_digest);
    if (strcmp(token_digest, permit.access_token_sha256) != 0) {
        secure_zero(token_digest, sizeof(token_digest));
        secure_zero(&permit, sizeof(permit));
        secure_zero(access_environment, mapping_size);
        munlock(access_environment, mapping_size);
        munmap(access_environment, mapping_size);
        close(executable);
        return fixed_error("credential_permit_mismatch");
    }
    access_environment[ACCESS_PREFIX_BYTES + token_length] = '\0';
    environment[0] = access_environment;
    if (emit_token_receipt(
            TOKEN_RECEIPT_FD, &descriptor, &permit,
            (const uint8_t *)(access_environment + ACCESS_PREFIX_BYTES),
            token_length, environment,
            codex_home_environment + sizeof("CODEX_HOME=") - 1U,
            &projection_deadline, token_receipt_digest) != 0
            || close(TOKEN_RECEIPT_FD) != 0) {
        secure_zero(token_digest, sizeof(token_digest));
        secure_zero(&permit, sizeof(permit));
        secure_zero(access_environment, mapping_size);
        munlock(access_environment, mapping_size);
        munmap(access_environment, mapping_size);
        close(executable);
        return fixed_error("token_receipt_failed");
    }
    if (wait_for_launch_gate(LAUNCH_GATE_FD, token_receipt_digest) != 0
            || close(LAUNCH_GATE_FD) != 0) {
        secure_zero(token_receipt_digest, sizeof(token_receipt_digest));
        secure_zero(token_digest, sizeof(token_digest));
        secure_zero(&permit, sizeof(permit));
        secure_zero(access_environment, mapping_size);
        munlock(access_environment, mapping_size);
        munmap(access_environment, mapping_size);
        close(executable);
        return fixed_error("launch_gate_failed");
    }
    {
        int model_length = snprintf(model_option, sizeof(model_option),
            "model=\"%s\"", descriptor.model_id);
        int reasoning_length = snprintf(
            reasoning_option, sizeof(reasoning_option),
            "model_reasoning_effort=\"%s\"", descriptor.reasoning_effort);
        if (model_length <= 0 || (size_t)model_length >= sizeof(model_option)
                || reasoning_length <= 0
                || (size_t)reasoning_length >= sizeof(reasoning_option)) {
            secure_zero(token_digest, sizeof(token_digest));
            secure_zero(&permit, sizeof(permit));
            secure_zero(access_environment, mapping_size);
            munlock(access_environment, mapping_size);
            munmap(access_environment, mapping_size);
            close(executable);
            return fixed_error("model_invalid");
        }
    }
    secure_zero(token_digest, sizeof(token_digest));
    secure_zero(token_receipt_digest, sizeof(token_receipt_digest));
    if (normalize_executable_descriptor(executable) != 0) {
        secure_zero(&permit, sizeof(permit));
        secure_zero(access_environment, mapping_size);
        munlock(access_environment, mapping_size);
        munmap(access_environment, mapping_size);
        close(EXECUTABLE_FD);
        return fixed_error("descriptor_hygiene_failed");
    }
    if (projection_permit_time_valid(&permit) != 0) {
        secure_zero(&permit, sizeof(permit));
        secure_zero(access_environment, mapping_size);
        munlock(access_environment, mapping_size);
        munmap(access_environment, mapping_size);
        close(EXECUTABLE_FD);
        return fixed_error("projection_permit_expired");
    }
    secure_zero(&permit, sizeof(permit));
    secure_zero(&descriptor, sizeof(descriptor));
    secure_zero(projection_id, sizeof(projection_id));
    fexecve(EXECUTABLE_FD, arguments, environment);
    secure_zero(access_environment, mapping_size);
    munlock(access_environment, mapping_size);
    munmap(access_environment, mapping_size);
    close(EXECUTABLE_FD);
    return fixed_error("exec_failed");
}

#else

static int test_frame(void) {
    char projection_id[37];
    uint32_t token_length = 0U;
    struct timespec projection_deadline;
    size_t mapping_size = 0U;
    char *buffer;
    if (start_io_deadline(&projection_deadline) != 0
            || parse_frame_header(
                STDIN_FILENO, projection_id, &token_length,
                &projection_deadline) != 0) {
        return fixed_error("projection_frame_invalid");
    }
    buffer = locked_token_buffer(token_length, &mapping_size);
    if (buffer == MAP_FAILED
            || read_exact_deadline(
                STDIN_FILENO, buffer, token_length, &projection_deadline) != 0
            || require_exact_eof(
                STDIN_FILENO, &projection_deadline) != 0
            || validate_token(buffer, token_length) != 0) {
        if (buffer != MAP_FAILED) {
            secure_zero(buffer, mapping_size);
            munlock(buffer, mapping_size);
            munmap(buffer, mapping_size);
        }
        return fixed_error("credential_frame_invalid");
    }
    secure_zero(buffer, mapping_size);
    munlock(buffer, mapping_size);
    munmap(buffer, mapping_size);
    (void)printf("projection_id=%s token_bytes=%" PRIu32 "\n", projection_id, token_length);
    return 0;
}

static int test_descriptor(const char *path) {
    struct launch_descriptor descriptor;
    if (load_descriptor(path, geteuid(), getegid(), &descriptor) != 0) {
        return fixed_error("launch_authority_invalid");
    }
    (void)printf(
        "descriptor_sha256=%s model_id=%s cyber_access_program=%s\n",
        descriptor.descriptor_sha256,
        descriptor.model_id,
        descriptor.cyber_access_program
    );
    secure_zero(&descriptor, sizeof(descriptor));
    return 0;
}

static int test_permit(const char *descriptor_path) {
    struct launch_descriptor descriptor;
    struct projection_permit permit;
    char projection_id[37];
    char observed_digest[65];
    uint32_t token_length = 0U;
    struct timespec projection_deadline;
    size_t mapping_size = 0U;
    char *buffer = MAP_FAILED;
    int result = 70;
    if (start_io_deadline(&projection_deadline) != 0
            || load_descriptor(descriptor_path, geteuid(), getegid(), &descriptor) != 0
            || parse_frame_header(
                STDIN_FILENO, projection_id, &token_length,
                &projection_deadline) != 0
            || load_projection_permit(
                PROJECTION_PERMIT_FD, geteuid(), getegid(), geteuid(), getegid(),
                &descriptor, projection_id, &permit) != 0
            || close(PROJECTION_PERMIT_FD) != 0) {
        (void)fixed_error("projection_permit_invalid");
        goto done;
    }
    buffer = locked_token_buffer(token_length, &mapping_size);
    if (buffer == MAP_FAILED || read_exact_deadline(
            STDIN_FILENO, buffer, token_length, &projection_deadline) != 0
            || require_exact_eof(STDIN_FILENO, &projection_deadline) != 0
            || validate_token(buffer, token_length) != 0) {
        (void)fixed_error("credential_frame_invalid");
        goto done;
    }
    sha256_bytes(buffer, token_length, observed_digest);
    if (strcmp(observed_digest, permit.access_token_sha256) != 0) {
        (void)fixed_error("credential_permit_mismatch");
        goto done;
    }
    (void)printf("permit_projection_id=%s session_id=%s token_bytes=%" PRIu32 "\n",
        permit.projection_id, permit.session_id, token_length);
    result = 0;
done:
    if (buffer != MAP_FAILED) {
        secure_zero(buffer, mapping_size);
        munlock(buffer, mapping_size);
        munmap(buffer, mapping_size);
    }
    secure_zero(observed_digest, sizeof(observed_digest));
    secure_zero(&permit, sizeof(permit));
    secure_zero(&descriptor, sizeof(descriptor));
    secure_zero(projection_id, sizeof(projection_id));
    return result;
}

static int test_token_receipt(const char *descriptor_path) {
    struct launch_descriptor descriptor;
    struct projection_permit permit;
    char projection_id[37];
    char observed_digest[65];
    uint32_t token_length = 0U;
    struct timespec projection_deadline;
    size_t mapping_size = 0U;
    char *buffer = MAP_FAILED;
    char codex_home[256];
    char codex_home_environment[320];
    char codex_config_environment[320];
    char codex_sqlite_environment[320];
    char home_environment[256];
    char cache_environment[256];
    char temporary_environment[256];
    char emitted_receipt_sha256[65];
    char *environment[] = {
        "ACCESS_TOKEN=content-not-inspected",
        codex_home_environment,
        codex_config_environment,
        codex_sqlite_environment,
        home_environment,
        cache_environment,
        temporary_environment,
        "LANG=C.UTF-8",
        "LC_ALL=C.UTF-8",
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "HTTP_PROXY=" CODEX_PROXY,
        "HTTPS_PROXY=" CODEX_PROXY,
        NULL,
    };
    int result = 70;
    if (start_io_deadline(&projection_deadline) != 0
            || load_descriptor(descriptor_path, geteuid(), getegid(), &descriptor) != 0
            || parse_frame_header(
                STDIN_FILENO, projection_id, &token_length,
                &projection_deadline) != 0
            || load_projection_permit(
                PROJECTION_PERMIT_FD, geteuid(), getegid(), geteuid(), getegid(),
                &descriptor, projection_id, &permit) != 0
            || close(PROJECTION_PERMIT_FD) != 0
            || snprintf(codex_home, sizeof(codex_home), "%s/%s/codex-home",
                SESSION_STATE_ROOT, descriptor.session_id) <= 0
            || format_session_environment(codex_home_environment,
                sizeof(codex_home_environment), "CODEX_HOME",
                descriptor.session_id, "codex-home") != 0
            || format_session_environment(codex_config_environment,
                sizeof(codex_config_environment), "XDG_CONFIG_HOME",
                descriptor.session_id, "codex-home") != 0
            || format_session_environment(codex_sqlite_environment,
                sizeof(codex_sqlite_environment), "CODEX_SQLITE_HOME",
                descriptor.session_id, "codex-home/state") != 0
            || format_session_environment(home_environment,
                sizeof(home_environment), "HOME",
                descriptor.session_id, "home") != 0
            || format_session_environment(cache_environment,
                sizeof(cache_environment), "XDG_CACHE_HOME",
                descriptor.session_id, "cache") != 0
            || format_session_environment(temporary_environment,
                sizeof(temporary_environment), "TMPDIR",
                descriptor.session_id, "tmp") != 0) {
        (void)fixed_error("projection_permit_invalid");
        goto done;
    }
    buffer = locked_token_buffer(token_length, &mapping_size);
    if (buffer == MAP_FAILED
            || read_exact_deadline(
                STDIN_FILENO, buffer, token_length, &projection_deadline) != 0
            || require_exact_eof(
                STDIN_FILENO, &projection_deadline) != 0
            || validate_token(buffer, token_length) != 0) {
        (void)fixed_error("credential_frame_invalid");
        goto done;
    }
    sha256_bytes(buffer, token_length, observed_digest);
    if (strcmp(observed_digest, permit.access_token_sha256) != 0) {
        (void)fixed_error("credential_permit_mismatch");
        goto done;
    }
    if (emit_token_receipt(
            TOKEN_RECEIPT_FD, &descriptor, &permit,
            (const uint8_t *)buffer, token_length,
            environment, codex_home, &projection_deadline,
            emitted_receipt_sha256) != 0
            || close(TOKEN_RECEIPT_FD) != 0) {
        (void)fixed_error("token_receipt_failed");
        goto done;
    }
    (void)printf("token_receipt_emitted\n");
    result = 0;
done:
    if (buffer != MAP_FAILED) {
        secure_zero(buffer, mapping_size);
        munlock(buffer, mapping_size);
        munmap(buffer, mapping_size);
    }
    secure_zero(observed_digest, sizeof(observed_digest));
    secure_zero(emitted_receipt_sha256, sizeof(emitted_receipt_sha256));
    secure_zero(&permit, sizeof(permit));
    secure_zero(&descriptor, sizeof(descriptor));
    secure_zero(projection_id, sizeof(projection_id));
    return result;
}

static int test_close_fds(const char *probe_text) {
    uint64_t probe_value;
    int null_descriptor;
    int probe;
    if (parse_uint64_canonical(probe_text, &probe_value) != 0
            || probe_value > INT_MAX || probe_value < 5U) {
        return fixed_error("probe_fd_invalid");
    }
    probe = (int)probe_value;
    null_descriptor = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (null_descriptor < 0) return fixed_error("keep_fd_invalid");
    if (null_descriptor != EXECUTABLE_FD) {
        if (dup2(null_descriptor, EXECUTABLE_FD) < 0 || close(null_descriptor) != 0) {
            return fixed_error("keep_fd_invalid");
        }
    }
    if (close_all_except(EXECUTABLE_FD) != 0
            || fcntl(EXECUTABLE_FD, F_GETFD) < 0) {
        return fixed_error("descriptor_hygiene_failed");
    }
    errno = 0;
    if (fcntl(probe, F_GETFD) >= 0 || errno != EBADF) {
        return fixed_error("probe_fd_survived");
    }
    close(EXECUTABLE_FD);
    (void)printf("closed_probe_fd=%d\n", probe);
    return 0;
}

static int test_launch_gate(const char *receipt_sha256) {
    if (wait_for_launch_gate(LAUNCH_GATE_FD, receipt_sha256) != 0
            || close(LAUNCH_GATE_FD) != 0) {
        return fixed_error("launch_gate_failed");
    }
    (void)printf("launch_gate_released\n");
    return 0;
}

static int test_permit_time(
    const char *issued_text, const char *expires_text, const char *now_text
) {
    struct projection_permit permit;
    uint64_t now;
    memset(&permit, 0, sizeof(permit));
    if (parse_uint64_canonical(
            issued_text, &permit.issued_at_unix) != 0
            || parse_uint64_canonical(
                expires_text, &permit.expires_at_unix) != 0
            || parse_uint64_canonical(now_text, &now) != 0
            || projection_permit_time_valid_at(&permit, now) != 0) {
        secure_zero(&permit, sizeof(permit));
        return fixed_error("projection_permit_expired");
    }
    secure_zero(&permit, sizeof(permit));
    (void)printf("projection_permit_current\n");
    return 0;
}

static int test_policy_tree(const char *path) {
    if (require_codex_policy_at(path, geteuid(), getegid()) != 0) {
        return fixed_error("codex_policy_invalid");
    }
    (void)printf("codex_policy_valid\n");
    return 0;
}

static int test_session_state(
    const char *path, const char *policy_path, const char *session_id
) {
    if (!is_uuid4(session_id)
            || require_session_state_at(
                path, policy_path, session_id,
                geteuid(), geteuid(), getegid()) != 0) {
        return fixed_error("session_state_invalid");
    }
    (void)printf("session_state_valid=%s\n", session_id);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--test-frame") == 0) return test_frame();
    if (argc == 3 && strcmp(argv[1], "--test-descriptor") == 0) {
        return test_descriptor(argv[2]);
    }
    if (argc == 3 && strcmp(argv[1], "--test-permit") == 0) {
        return test_permit(argv[2]);
    }
    if (argc == 3 && strcmp(argv[1], "--test-token-receipt") == 0) {
        return test_token_receipt(argv[2]);
    }
    if (argc == 3 && strcmp(argv[1], "--test-close-fds") == 0) {
        return test_close_fds(argv[2]);
    }
    if (argc == 3 && strcmp(argv[1], "--test-launch-gate") == 0) {
        return test_launch_gate(argv[2]);
    }
    if (argc == 5 && strcmp(argv[1], "--test-permit-time") == 0) {
        return test_permit_time(argv[2], argv[3], argv[4]);
    }
    if (argc == 3 && strcmp(argv[1], "--test-policy-tree") == 0) {
        return test_policy_tree(argv[2]);
    }
    if (argc == 5 && strcmp(argv[1], "--test-session-state") == 0) {
        return test_session_state(argv[2], argv[3], argv[4]);
    }
    return fixed_error("test_usage_invalid");
}

#endif
