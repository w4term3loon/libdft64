#include <unistd.h>

int main(void) {
    char buffer[32]; // Small buffer to read a "word"
    size_t bytes_read;

    // 1. Read a "word" (whatever fits in one read call up to buffer size) from stdin
    bytes_read = read(STDIN_FILENO, buffer, sizeof(buffer) - 1);

    // 2. Output that "word" to stdout, if anything was read
    if (bytes_read > 0) {
        write(STDOUT_FILENO, buffer, bytes_read);
    }

    // 3. Output a simple greeting to stdout
    char greeting[] = "Hi!\n"; // Greeting string
    write(STDOUT_FILENO, greeting, sizeof(greeting) - 1); // sizeof()-1 for string literal length

    return 0;
}
