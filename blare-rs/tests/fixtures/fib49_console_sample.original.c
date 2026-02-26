#include <windows.h>
#include <stdint.h>

static HANDLE g_out;
static HANDLE g_in;

static void write_buf(const char *buf, DWORD len) {
    DWORD written = 0;
    if (g_out != INVALID_HANDLE_VALUE) {
        WriteFile(g_out, buf, len, &written, NULL);
    }
}

static DWORD cstr_len(const char *s) {
    DWORD n = 0;
    while (s[n] != '\0') {
        n++;
    }
    return n;
}

static void write_str(const char *s) {
    write_buf(s, cstr_len(s));
}

static void write_u32_2digits(unsigned v) {
    char b[2];
    b[0] = (char)('0' + (v / 10U) % 10U);
    b[1] = (char)('0' + (v % 10U));
    write_buf(b, 2);
}

static void write_u64(uint64_t v) {
    char tmp[32];
    DWORD pos = 0;
    if (v == 0) {
        write_buf("0", 1);
        return;
    }
    while (v > 0 && pos < (DWORD)sizeof(tmp)) {
        tmp[pos++] = (char)('0' + (v % 10ULL));
        v /= 10ULL;
    }
    while (pos > 0) {
        pos--;
        write_buf(&tmp[pos], 1);
    }
}

static void wait_for_enter(void) {
    if (g_in == INVALID_HANDLE_VALUE) {
        return;
    }

    for (;;) {
        char ch = 0;
        DWORD read = 0;
        if (ReadFile(g_in, &ch, 1, &read, NULL) && read == 1) {
            if (ch == '\r' || ch == '\n') {
                return;
            }
            continue;
        }
        Sleep(50);
    }
}

void mainCRTStartup(void) {
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);
    g_in = GetStdHandle(STD_INPUT_HANDLE);

    write_str("49 premiers nombres de Fibonacci:\r\n");

    uint64_t a = 0;
    uint64_t b = 1;
    for (unsigned i = 0; i < 49; i++) {
        write_str("fib(");
        write_u32_2digits(i);
        write_str(") = ");
        write_u64(a);
        write_str("\r\n");
        uint64_t n = a + b;
        a = b;
        b = n;
    }

    write_str("\r\nAppuyez sur Entree pour fermer...\r\n");
    wait_for_enter();

    ExitProcess(0);
}
