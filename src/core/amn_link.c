#define _GNU_SOURCE

#include <errno.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define REQUEST_SIZE 4096

struct link_request {
    struct nlmsghdr header;
    struct ifinfomsg interface;
    unsigned char attributes[REQUEST_SIZE];
};

static void fail(const char *message) {
    fprintf(stderr, "amn-link: %s: %s\n", message, strerror(errno));
    exit(EXIT_FAILURE);
}

static void invalid(const char *message) {
    fprintf(stderr, "amn-link: %s\n", message);
    exit(EXIT_FAILURE);
}

static int open_netlink(void) {
    int socket_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (socket_fd < 0) {
        fail("open route netlink socket");
    }
    struct sockaddr_nl address = {
        .nl_family = AF_NETLINK,
    };
    if (bind(socket_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        fail("bind route netlink socket");
    }
    return socket_fd;
}

static void add_attribute(struct nlmsghdr *header, size_t capacity, uint16_t type,
                          const void *data, size_t length) {
    size_t attribute_length = RTA_LENGTH(length);
    size_t new_length = NLMSG_ALIGN(header->nlmsg_len) + RTA_ALIGN(attribute_length);
    if (new_length > capacity) {
        invalid("netlink request is too large");
    }
    struct rtattr *attribute =
        (struct rtattr *)((unsigned char *)header + NLMSG_ALIGN(header->nlmsg_len));
    attribute->rta_type = type;
    attribute->rta_len = attribute_length;
    if (length > 0) {
        memcpy(RTA_DATA(attribute), data, length);
    }
    header->nlmsg_len = new_length;
}

static struct rtattr *begin_nested(struct nlmsghdr *header, size_t capacity, uint16_t type) {
    struct rtattr *nested =
        (struct rtattr *)((unsigned char *)header + NLMSG_ALIGN(header->nlmsg_len));
    add_attribute(header, capacity, type, NULL, 0);
    return nested;
}

static void end_nested(struct nlmsghdr *header, struct rtattr *nested) {
    nested->rta_len =
        (uint16_t)((unsigned char *)header + NLMSG_ALIGN(header->nlmsg_len) -
                   (unsigned char *)nested);
}

static void send_acknowledged(int socket_fd, struct nlmsghdr *header) {
    static uint32_t sequence = 1;
    header->nlmsg_seq = sequence++;
    struct sockaddr_nl address = {
        .nl_family = AF_NETLINK,
    };
    struct iovec vector = {
        .iov_base = header,
        .iov_len = header->nlmsg_len,
    };
    struct msghdr message = {
        .msg_name = &address,
        .msg_namelen = sizeof(address),
        .msg_iov = &vector,
        .msg_iovlen = 1,
    };
    if (sendmsg(socket_fd, &message, 0) < 0) {
        fail("send route netlink request");
    }

    unsigned char response[REQUEST_SIZE];
    for (;;) {
        ssize_t received = recv(socket_fd, response, sizeof(response), 0);
        if (received < 0) {
            fail("receive route netlink acknowledgement");
        }
        for (struct nlmsghdr *reply = (struct nlmsghdr *)response;
             NLMSG_OK(reply, (unsigned int)received); reply = NLMSG_NEXT(reply, received)) {
            if (reply->nlmsg_seq != header->nlmsg_seq) {
                continue;
            }
            if (reply->nlmsg_type != NLMSG_ERROR) {
                continue;
            }
            struct nlmsgerr *error = NLMSG_DATA(reply);
            if (error->error == 0) {
                return;
            }
            errno = -error->error;
            fail("route netlink request rejected");
        }
    }
}

static unsigned int parse_index(const char *value) {
    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(value, &end, 10);
    if (errno != 0 || value[0] == '\0' || end == NULL || *end != '\0' || parsed == 0 ||
        parsed > UINT32_MAX) {
        invalid("interface index is invalid");
    }
    return (unsigned int)parsed;
}

static void validate_text(const char *value, size_t maximum, const char *message) {
    size_t length = strlen(value);
    if (length == 0 || length > maximum) {
        invalid(message);
    }
}

static void owner_identity(const char *owner, unsigned int *index, uint32_t *group) {
    char hexadecimal[33];
    size_t written = 0;
    for (const char *cursor = owner; *cursor != '\0'; ++cursor) {
        if (*cursor == '-') {
            continue;
        }
        if (written >= 32 || !((*cursor >= '0' && *cursor <= '9') ||
                               (*cursor >= 'a' && *cursor <= 'f') ||
                               (*cursor >= 'A' && *cursor <= 'F'))) {
            invalid("interface owner is not a UUID");
        }
        hexadecimal[written++] = *cursor;
    }
    if (written != 32) {
        invalid("interface owner is not a UUID");
    }
    hexadecimal[32] = '\0';
    char index_text[8];
    memcpy(index_text, hexadecimal, 7);
    index_text[7] = '\0';
    char group_text[9];
    memcpy(group_text, hexadecimal + 8, 8);
    group_text[8] = '\0';
    *index = (unsigned int)strtoul(index_text, NULL, 16) + 1024U;
    *group = (uint32_t)strtoul(group_text, NULL, 16) | UINT32_C(0x80000000);
}

static void set_attributes(unsigned int index, uint16_t type, const char *value);
static bool inspect_index(unsigned int index, const char *owner, uint32_t *group);

static void create_owned(const char *kind, const char *name, const char *owner) {
    validate_text(kind, 31, "interface kind is invalid");
    validate_text(name, IFNAMSIZ - 1, "interface name is invalid");
    validate_text(owner, 255, "interface owner is invalid");

    unsigned int expected_index;
    uint32_t expected_group;
    owner_identity(owner, &expected_index, &expected_group);
    int socket_fd = open_netlink();
    struct link_request request = {0};
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(request.interface));
    request.header.nlmsg_type = RTM_NEWLINK;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    request.interface.ifi_family = AF_UNSPEC;
    request.interface.ifi_index = (int)expected_index;
    add_attribute(&request.header, sizeof(request), IFLA_IFNAME, name, strlen(name) + 1);
    add_attribute(&request.header, sizeof(request), IFLA_GROUP, &expected_group, sizeof(expected_group));
    struct rtattr *link_info = begin_nested(&request.header, sizeof(request), IFLA_LINKINFO);
    add_attribute(&request.header, sizeof(request), IFLA_INFO_KIND, kind, strlen(kind) + 1);
    end_nested(&request.header, link_info);
    send_acknowledged(socket_fd, &request.header);
    close(socket_fd);

    unsigned int index = if_nametoindex(name);
    if (index == 0 || index != expected_index) {
        fail("read created interface index");
    }
    uint32_t actual_group;
    (void)inspect_index(index, "", &actual_group);
    if (actual_group != expected_group || if_nametoindex(name) != index) {
        invalid("created interface lost its precommitted identity");
    }
    set_attributes(index, IFLA_IFALIAS, owner);
    printf("%u\n", index);
}

static void set_attributes(unsigned int index, uint16_t type, const char *value) {
    int socket_fd = open_netlink();
    struct link_request request = {0};
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(request.interface));
    request.header.nlmsg_type = RTM_SETLINK;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    request.interface.ifi_family = AF_UNSPEC;
    request.interface.ifi_index = (int)index;
    add_attribute(&request.header, sizeof(request), type, value, strlen(value) + 1);
    send_acknowledged(socket_fd, &request.header);
    close(socket_fd);
}

static bool inspect_index(unsigned int index, const char *owner, uint32_t *group) {
    int socket_fd = open_netlink();
    struct link_request request = {0};
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(request.interface));
    request.header.nlmsg_type = RTM_GETLINK;
    request.header.nlmsg_flags = NLM_F_REQUEST;
    request.interface.ifi_family = AF_UNSPEC;
    request.interface.ifi_index = (int)index;
    static uint32_t sequence = 1000000;
    request.header.nlmsg_seq = sequence++;

    struct sockaddr_nl address = {.nl_family = AF_NETLINK};
    struct iovec vector = {.iov_base = &request, .iov_len = request.header.nlmsg_len};
    struct msghdr message = {
        .msg_name = &address,
        .msg_namelen = sizeof(address),
        .msg_iov = &vector,
        .msg_iovlen = 1,
    };
    if (sendmsg(socket_fd, &message, 0) < 0) {
        fail("request interface identity");
    }

    unsigned char response[REQUEST_SIZE];
    ssize_t received = recv(socket_fd, response, sizeof(response), 0);
    if (received < 0) {
        fail("read interface identity");
    }
    bool matches = owner[0] == '\0';
    if (group != NULL) {
        *group = UINT32_MAX;
    }
    for (struct nlmsghdr *reply = (struct nlmsghdr *)response;
         NLMSG_OK(reply, (unsigned int)received); reply = NLMSG_NEXT(reply, received)) {
        if (reply->nlmsg_seq != request.header.nlmsg_seq) {
            continue;
        }
        if (reply->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *error = NLMSG_DATA(reply);
            if (error->error != 0) {
                errno = -error->error;
                fail("inspect interface identity");
            }
            continue;
        }
        if (reply->nlmsg_type != RTM_NEWLINK) {
            continue;
        }
        struct ifinfomsg *interface = NLMSG_DATA(reply);
        if ((unsigned int)interface->ifi_index != index) {
            continue;
        }
        int remaining = IFLA_PAYLOAD(reply);
        for (struct rtattr *attribute = IFLA_RTA(interface); RTA_OK(attribute, remaining);
             attribute = RTA_NEXT(attribute, remaining)) {
            if (attribute->rta_type == IFLA_IFALIAS) {
                const char *actual = RTA_DATA(attribute);
                size_t available = RTA_PAYLOAD(attribute);
                matches = strnlen(actual, available) == strlen(owner) &&
                          memcmp(actual, owner, strlen(owner)) == 0;
            } else if (attribute->rta_type == IFLA_GROUP && group != NULL &&
                       RTA_PAYLOAD(attribute) == sizeof(*group)) {
                memcpy(group, RTA_DATA(attribute), sizeof(*group));
            }
        }
    }
    close(socket_fd);
    return matches;
}

static bool owned_index(unsigned int index, const char *owner) {
    return inspect_index(index, owner, NULL);
}

static bool planned_unaliased_index(const char *name, const char *owner, unsigned int *index) {
    validate_text(name, IFNAMSIZ - 1, "interface name is invalid");
    uint32_t expected_group;
    owner_identity(owner, index, &expected_group);
    if (if_nametoindex(name) != *index) {
        return false;
    }
    uint32_t actual_group;
    bool alias_is_empty = inspect_index(*index, "", &actual_group);
    return alias_is_empty && actual_group == expected_group && if_nametoindex(name) == *index;
}

static unsigned int owned_name(const char *name, const char *owner) {
    validate_text(name, IFNAMSIZ - 1, "interface name is invalid");
    unsigned int index = if_nametoindex(name);
    if (index == 0) {
        fail("resolve interface index");
    }
    if (!owned_index(index, owner)) {
        invalid("interface ownership alias does not match");
    }
    return index;
}

static void delete_owned(unsigned int index, const char *owner) {
    if (!owned_index(index, owner)) {
        invalid("interface ownership alias does not match");
    }
    int socket_fd = open_netlink();
    struct link_request request = {0};
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(request.interface));
    request.header.nlmsg_type = RTM_DELLINK;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    request.interface.ifi_family = AF_UNSPEC;
    request.interface.ifi_index = (int)index;
    send_acknowledged(socket_fd, &request.header);
    close(socket_fd);
}

static void usage(void) {
    fputs("usage: amn-link create KIND NAME OWNER | claim NAME OWNER | recover NAME OWNER | verify INDEX OWNER | verify-name INDEX OWNER NAME | rename INDEX OWNER NAME | delete-index INDEX OWNER | delete-name NAME OWNER\n", stderr);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    if (argc == 5 && strcmp(argv[1], "create") == 0) {
        create_owned(argv[2], argv[3], argv[4]);
        return EXIT_SUCCESS;
    }
    if (argc == 4 && strcmp(argv[1], "claim") == 0) {
        unsigned int index = if_nametoindex(argv[2]);
        if (index == 0) {
            fail("resolve interface index");
        }
        set_attributes(index, IFLA_IFALIAS, argv[3]);
        if (!owned_index(index, argv[3])) {
            invalid("interface ownership alias did not persist");
        }
        printf("%u\n", index);
        return EXIT_SUCCESS;
    }
    if (argc == 4 && strcmp(argv[1], "recover") == 0) {
        unsigned int index;
        if (!planned_unaliased_index(argv[2], argv[3], &index)) {
            invalid("unaliased interface does not match the precommitted identity");
        }
        set_attributes(index, IFLA_IFALIAS, argv[3]);
        if (!owned_index(index, argv[3])) {
            invalid("recovered interface ownership alias did not persist");
        }
        printf("%u\n", index);
        return EXIT_SUCCESS;
    }
    if (argc == 4 && strcmp(argv[1], "verify") == 0) {
        if (!owned_index(parse_index(argv[2]), argv[3])) {
            invalid("interface ownership alias does not match");
        }
        return EXIT_SUCCESS;
    }
    if (argc == 5 && strcmp(argv[1], "verify-name") == 0) {
        unsigned int index = parse_index(argv[2]);
        validate_text(argv[4], IFNAMSIZ - 1, "interface name is invalid");
        if (!owned_index(index, argv[3]) || if_nametoindex(argv[4]) != index) {
            invalid("interface name, index, and ownership alias do not match");
        }
        return EXIT_SUCCESS;
    }
    if (argc == 5 && strcmp(argv[1], "rename") == 0) {
        unsigned int index = parse_index(argv[2]);
        if (!owned_index(index, argv[3])) {
            invalid("interface ownership alias does not match");
        }
        validate_text(argv[4], IFNAMSIZ - 1, "interface name is invalid");
        set_attributes(index, IFLA_IFNAME, argv[4]);
        if (!owned_index(index, argv[3])) {
            invalid("renamed interface ownership alias changed");
        }
        return EXIT_SUCCESS;
    }
    if (argc == 4 && strcmp(argv[1], "delete-index") == 0) {
        delete_owned(parse_index(argv[2]), argv[3]);
        return EXIT_SUCCESS;
    }
    if (argc == 4 && strcmp(argv[1], "delete-name") == 0) {
        delete_owned(owned_name(argv[2], argv[3]), argv[3]);
        return EXIT_SUCCESS;
    }
    usage();
}
