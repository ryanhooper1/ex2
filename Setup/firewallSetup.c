#include <stdio.h>    
#include <stdlib.h>   
#include <string.h>   
#include <unistd.h>   
#include <fcntl.h>    
#include <errno.h>    

//Constants
#define PROC_PATH    "/proc/firewallExtension"
#define MAX_PATH_LEN 256
#define MAX_LINE_LEN 300   
#define MAX_RULES    64

//Rule structure
struct rule {
    int  port;
    char program[MAX_PATH_LEN];
};

// Helper function
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

// Helper function 
static void cmd_write(const char *filename)
{
    FILE *fp;
    char  line[MAX_LINE_LEN];

    struct rule rules[MAX_RULES];
    int    num_rules = 0;

    char   send_buf[MAX_RULES * (MAX_PATH_LEN + 16)];
    int    send_len = 0;

    int  port;
    char prog[MAX_PATH_LEN];

    int  fd;
    ssize_t written;

    fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: could not open rules file '%s': %s\n",
                filename, strerror(errno));
        exit(1);
    }

    //Parse
    while (fgets(line, sizeof(line), fp) != NULL) {

        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';

        if (strlen(line) == 0)
            continue;

        if (sscanf(line, "%d %255s", &port, prog) != 2) {
            fprintf(stderr, "ERROR: Ill-formed file\n");
            fclose(fp);
            exit(1);
        }

        if (port < 1 || port > 65535) {
            fprintf(stderr, "ERROR: Ill-formed file\n");
            fclose(fp);
            exit(1);
        }

        if (prog[0] != '/') {
            fprintf(stderr, "ERROR: Ill-formed file\n");
            fclose(fp);
            exit(1);
        }

        // Validate that the program exists and is executable

        if (access(prog, F_OK) != 0) {
            fprintf(stderr, "ERROR: Cannot execute file\n");
            fclose(fp);
            exit(1);
        }
        if (access(prog, X_OK) != 0) {
            fprintf(stderr, "ERROR: Cannot execute file\n");
            fclose(fp);
            exit(1);
        }

        if (num_rules >= MAX_RULES) {
            fprintf(stderr, "ERROR: Ill-formed file\n");
            fclose(fp);
            exit(1);
        }

        rules[num_rules].port = port;
        strncpy(rules[num_rules].program, prog, MAX_PATH_LEN - 1);
        rules[num_rules].program[MAX_PATH_LEN - 1] = '\0';
        num_rules++;
    }

    fclose(fp);

    //Build the buffer
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

    // Send the buffer to the kernel 
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



int main(int argc, char *argv[])
{

    if (argc < 2) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s L              (list rules in kern.log)\n", argv[0]);
        fprintf(stderr, "  %s W <filename>   (load rules from file)\n",   argv[0]);
        return 1;
    }
    
    if (strcmp(argv[1], "L") == 0) {
        if (argc != 2) {
            fprintf(stderr, "Usage: %s L\n", argv[0]);
            return 1;
        }
        cmd_list();
    }
    
    else if (strcmp(argv[1], "W") == 0) {
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