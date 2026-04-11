/*
 * firewallSetup.c  (place in directory: Setup/)
 *
 * User-space program for configuring the firewall kernel module.
 * Communicates with the kernel via /proc/firewallExtension.
 *
 * Usage:
 *   ./firewallSetup L
 *       Tells the kernel module to print all current rules to /var/log/kern.log
 *
 *   ./firewallSetup W <filename>
 *       Reads firewall rules from <filename> (one "port /path" rule per line)
 *       and sends them to the kernel module, replacing the existing rule set.
 *       Each path is validated as an existing executable before sending.
 *
 * Error messages (as specified):
 *   "ERROR: Ill-formed file"    — syntax error in the rules file
 *   "ERROR: Cannot execute file" — a listed program is not an executable file
 *
 * Author: [your name]
 * References:
 *   - open(2), write(2), access(2): https://man7.org/linux/man-pages/
 *   - CS module lecture notes on process/file interaction
 */

#include <stdio.h>    /* printf, fprintf, fopen, fgets */
#include <stdlib.h>   /* exit */
#include <string.h>   /* strlen, strncpy, snprintf */
#include <unistd.h>   /* access(), X_OK */
#include <fcntl.h>    /* open(), O_WRONLY */
#include <errno.h>    /* errno */

#define PROC_PATH    "/proc/firewallExtension"
#define MAX_PATH_LEN 256
#define MAX_LINE_LEN 300   /* port (up to 5 digits) + space + path + newline */
#define MAX_RULES    64

/*
 * Structure to hold one parsed rule before we send it to the kernel.
 * We validate all rules before sending any, to ensure atomicity:
 * either the whole new set is sent, or nothing is sent.
 */
struct rule {
    int  port;
    char program[MAX_PATH_LEN];
};

/* -------------------------------------------------------------------------
 * cmd_list: handles "firewallSetup L"
 *
 * Writes the string "LIST\n" to the proc file, which instructs the kernel
 * module to print all current firewall rules to /var/log/kern.log.
 * ------------------------------------------------------------------------- */
static void cmd_list(void)
{
    int fd;
    const char *msg = "LIST\n";
    ssize_t written;

    fd = open(PROC_PATH, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "Error: could not open %s: %s\n",
                PROC_PATH, strerror(errno));
        exit(1);
    }

    written = write(fd, msg, strlen(msg));
    if (written < 0) {
        fprintf(stderr, "Error: write to %s failed: %s\n",
                PROC_PATH, strerror(errno));
        close(fd);
        exit(1);
    }

    close(fd);
    printf("Rules listed in /var/log/kern.log\n");
}

/* -------------------------------------------------------------------------
 * cmd_write: handles "firewallSetup W <filename>"
 *
 * Reads rules from <filename>, validates them all, then writes the full
 * set to the kernel module in one write() call.
 *
 * Validation:
 *   1. Each line must have the form: <integer> <string>  (else: Ill-formed)
 *   2. Port must be in range 1–65535                     (else: Ill-formed)
 *   3. The program path must be an existing executable   (else: Cannot execute)
 *
 * We validate ALL rules first. Only if everything is valid do we write to
 * the kernel. This ensures that a bad file does not partially update rules.
 * ------------------------------------------------------------------------- */
static void cmd_write(const char *filename)
{
    FILE *fp;
    char  line[MAX_LINE_LEN];
    int   line_number = 0;

    struct rule rules[MAX_RULES];
    int    num_rules = 0;

    /* Buffer we will write to the kernel — build it up as we parse */
    char   send_buf[MAX_RULES * (MAX_PATH_LEN + 16)];
    int    send_len = 0;

    int  port;
    char prog[MAX_PATH_LEN];

    int  fd;
    ssize_t written;

    /* Open the rules file */
    fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: could not open rules file '%s': %s\n",
                filename, strerror(errno));
        exit(1);
    }

    /*
     * Read and validate every line before sending anything.
     * This ensures we either send a fully-valid set or nothing at all.
     */
    while (fgets(line, sizeof(line), fp) != NULL) {
        line_number++;

        /* Strip trailing newline for cleaner error messages */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';

        /* Skip blank lines */
        if (strlen(line) == 0)
            continue;

        /* Parse the line: expect exactly "integer string" */
        if (sscanf(line, "%d %255s", &port, prog) != 2) {
            fprintf(stderr, "ERROR: Ill-formed file\n");
            fclose(fp);
            exit(1);
        }

        /* Port must be a valid TCP port number (1–65535) */
        if (port < 1 || port > 65535) {
            fprintf(stderr, "ERROR: Ill-formed file\n");
            fclose(fp);
            exit(1);
        }

        /* Path must start with '/' — we only accept full/absolute paths */
        if (prog[0] != '/') {
            fprintf(stderr, "ERROR: Ill-formed file\n");
            fclose(fp);
            exit(1);
        }

        /*
         * Check that the program is an existing, executable file.
         * access(path, X_OK) returns 0 if the file exists and is executable.
         * Reference: man 2 access, https://man7.org/linux/man-pages/man2/access.2.html
         */
        if (access(prog, F_OK) != 0) {
            /* File does not exist at all */
            fprintf(stderr, "ERROR: Cannot execute file\n");
            fclose(fp);
            exit(1);
        }
        if (access(prog, X_OK) != 0) {
            /* File exists but is not executable */
            fprintf(stderr, "ERROR: Cannot execute file\n");
            fclose(fp);
            exit(1);
        }

        /* Enforce maximum rule count */
        if (num_rules >= MAX_RULES) {
            fprintf(stderr, "ERROR: Ill-formed file\n");
            fclose(fp);
            exit(1);
        }

        /* Store validated rule */
        rules[num_rules].port = port;
        strncpy(rules[num_rules].program, prog, MAX_PATH_LEN - 1);
        rules[num_rules].program[MAX_PATH_LEN - 1] = '\0';
        num_rules++;
    }

    fclose(fp);

    /*
     * All rules are valid. Now build the write buffer.
     * Format: one rule per line — "port /full/path\n"
     * This is the format the kernel module's proc_write handler expects.
     */
    send_len = 0;
    for (int i = 0; i < num_rules; i++) {
        int n = snprintf(send_buf + send_len,
                         sizeof(send_buf) - send_len,
                         "%d %s\n",
                         rules[i].port,
                         rules[i].program);
        if (n < 0 || (send_len + n) >= (int)sizeof(send_buf)) {
            fprintf(stderr, "Error: output buffer overflow\n");
            exit(1);
        }
        send_len += n;
    }

    /*
     * Open and write to /proc/firewallExtension.
     * The kernel module will parse and atomically replace its rule set.
     * If this write fails, the kernel retains its old rules.
     */
    fd = open(PROC_PATH, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "Error: could not open %s: %s\n",
                PROC_PATH, strerror(errno));
        exit(1);
    }

    if (send_len > 0) {
        written = write(fd, send_buf, send_len);
        if (written < 0) {
            fprintf(stderr, "Error: write to %s failed: %s\n",
                    PROC_PATH, strerror(errno));
            close(fd);
            exit(1);
        }
    }

    close(fd);
    printf("Loaded %d rule(s) from '%s'\n", num_rules, filename);
}

/* -------------------------------------------------------------------------
 * main — parse command-line arguments and dispatch
 * ------------------------------------------------------------------------- */
int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s L              (list rules in kern.log)\n", argv[0]);
        fprintf(stderr, "  %s W <filename>   (load rules from file)\n",   argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "L") == 0) {
        /* List command — no other arguments needed */
        if (argc != 2) {
            fprintf(stderr, "Usage: %s L\n", argv[0]);
            return 1;
        }
        cmd_list();
    }
    else if (strcmp(argv[1], "W") == 0) {
        /* Write command — requires a filename */
        if (argc != 3) {
            fprintf(stderr, "Usage: %s W <filename>\n", argv[0]);
            return 1;
        }
        cmd_write(argv[2]);
    }
    else {
        fprintf(stderr, "Unknown command '%s'. Use L or W.\n", argv[1]);
        return 1;
    }

    return 0;
}