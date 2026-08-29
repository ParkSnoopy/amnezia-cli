#include <amnezia_xray.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested = 0;
static volatile sig_atomic_t child_pid = -1;

static void request_stop(int signal_number)
{
    (void) signal_number;
    stop_requested = 1;
    if (child_pid > 0) {
        kill((pid_t) child_pid, SIGTERM);
    }
}

static char *read_configuration(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL || fseek(file, 0, SEEK_END) != 0) {
        if (file != NULL) fclose(file);
        return NULL;
    }
    long length = ftell(file);
    if (length <= 0 || length > 16 * 1024 * 1024 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }
    char *buffer = calloc((size_t) length + 1, 1);
    if (buffer == NULL || fread(buffer, 1, (size_t) length, file) != (size_t) length) {
        free(buffer);
        fclose(file);
        return NULL;
    }
    fclose(file);
    return buffer;
}

static int xray_call(const char *operation, char *error)
{
    if (error == NULL) return 0;
    fprintf(stderr, "XRay %s failed\n", operation);
    amnezia_xray_free(error);
    return 1;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--check") == 0) return 0;
    if (argc != 7) {
        fprintf(stderr, "internal XRay runner expects configuration, tun2socks, interface, endpoint, gateway, and uplink\n");
        return 2;
    }
    char *configuration = read_configuration(argv[1]);
    if (configuration == NULL) {
        fprintf(stderr, "cannot read staged XRay configuration\n");
        return 1;
    }
    if (xray_call("configure", amnezia_xray_configure(configuration)) != 0) {
        free(configuration);
        return 1;
    }
    free(configuration);
    if (xray_call("start", amnezia_xray_start()) != 0) return 1;

    struct sigaction action = {0};
    action.sa_handler = request_stop;
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);

    pid_t pid = fork();
    if (pid == 0) {
        char device[64];
        if (snprintf(device, sizeof(device), "tun://%s", argv[3]) >= (int) sizeof(device)) _exit(2);
        execl(argv[2], argv[2], "-device", device, "-proxy", "socks5://127.0.0.1:10808", (char *) NULL);
        _exit(127);
    }
    if (pid < 0) {
        xray_call("stop", amnezia_xray_stop());
        return 1;
    }
    child_pid = pid;

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR && stop_requested) {
            kill(pid, SIGTERM);
            continue;
        }
        if (errno != EINTR) {
            status = 1;
            break;
        }
    }
    child_pid = -1;
    int stop_failed = xray_call("stop", amnezia_xray_stop());
    if (stop_requested && stop_failed == 0) return 0;
    if (stop_failed != 0) return 1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 1;
}
