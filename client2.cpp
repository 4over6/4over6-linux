#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <pth.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

char server_addr[32] = "2402:f000:1:1141::410";
char tun_name[IFNAMSIZ] = "4over6";
int tun_fd;

struct Msg {
  uint32_t length;
  uint8_t type;
  uint8_t data[4096];
};

const static int HEADER_LEN = sizeof(uint32_t) + sizeof(uint8_t);

int run_cmd(const char *cmd, ...) {
  va_list ap;
  char buf[1024];
  va_start(ap, cmd);
  vsnprintf(buf, sizeof(buf), cmd, ap);
  va_end(ap);
  return pth_system(buf);
}

int print(const char *fmt, ...) {
  va_list ap;
  char buf[1024];
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  char print_buf[1024];
  pth_t cur = pth_self();
  char *thread_name;
  pth_attr_get(pth_attr_of(cur), PTH_ATTR_NAME, &thread_name);
  snprintf(print_buf, sizeof(print_buf), "%s: %s", thread_name, buf);
  return fputs(print_buf, stdout);
}

int tun_alloc(char *dev) {
  struct ifreq ifr = {0};
  int fd, err;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    perror("Cannot open TUN dev");
    exit(1);
  }

  /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
   *        IFF_TAP   - TAP device
   *
   *        IFF_NO_PI - Do not provide packet information
   */
  ifr.ifr_flags = IFF_TUN;
  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
    perror("Cannot initialize TUN device");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);
  return fd;
}

uint8_t *read_exact(int fd, size_t len) {
  size_t read_length = 0;
  uint8_t *buffer = (uint8_t *)malloc(len);
  uint8_t *ptr = buffer;
  while (read_length < len) {
    ssize_t read_bytes = pth_read(fd, ptr, len - read_length);
    if (read_bytes < 0) {
      if (read_bytes == EAGAIN || read_bytes == EWOULDBLOCK) {
        continue;
      } else if (read_bytes == -1) {
        if (errno == EAGAIN) {
          continue;
        }
        perror("read");
        assert(false);
      }
    } else {
      read_length += read_bytes;
      ptr += read_bytes;
    }
  }

  return buffer;
}

void *server_read(void *arg) {
  int socket_fd = (int)(size_t)arg;
  uint8_t buffer[4096];
  struct tun_pi *pi = (struct tun_pi *)buffer;
  pi->flags = 0;
  pi->proto = htons(ETH_P_IP);
  while (1) {
    struct Msg *msg = (struct Msg *)read_exact(socket_fd, HEADER_LEN);
    size_t len = msg->length - HEADER_LEN;
    if (len > 0) {
      uint8_t *body = read_exact(socket_fd, len);
      if (msg->type == 103) {
        memcpy(buffer + sizeof(struct tun_pi), body, len);
        pth_write(tun_fd, buffer, len + sizeof(struct tun_pi));
      } else if (msg->type == 101) {
        char ip[32], route[32], dns1[32], dns2[32], dns3[32];

        char buffer[1024];
        memcpy(buffer, body, len);
        buffer[len] = '\0';

        sscanf(buffer, "%s %s %s %s %s", ip, route, dns1, dns2, dns3);

        printf("Got ip addr %s\n", ip);
        run_cmd("ip -n %s a add local %s/32 dev %s", tun_name, ip,
                tun_name);
        printf("Got ip route %s\n", route);
        run_cmd("ip -n %s r add %s/0 dev %s", tun_name, route, tun_name);

      } else {
        print("Unrecognised msg type: %d\n", msg->type);
      }
      free(body);
    }
    free(msg);
  }
  return NULL;
}

void *tun_read(void *arg) {
  int socket_fd = (int)(size_t)arg;
  uint8_t buffer[4096];
  while (1) {
    uint8_t *current = buffer;
    ssize_t read_bytes = pth_read(tun_fd, buffer, sizeof(buffer));
    if (read_bytes < 0) {
      perror("pth_read");
      continue;
    }
    uint8_t *end = current + read_bytes;

    struct tun_pi *pi = (struct tun_pi *)current;
    current += sizeof(struct tun_pi);
    assert(current <= end);

    uint16_t proto = ntohs(pi->proto);
    if (proto == ETH_P_IP) {
      struct iphdr *hdr = (struct iphdr *)current;
      if (hdr->version == 4) {
        uint8_t *ip = current;
        uint16_t len = ntohs(hdr->tot_len);
        uint8_t header_len = hdr->ihl * 4;
        current += header_len;
        assert(current <= end);

        uint8_t *body = current;
        uint16_t body_len = len - header_len;
        current += body_len;
        assert(current == end);

        struct Msg data = {.type = 102};
        memcpy(data.data, ip, len);
        data.length = len + HEADER_LEN;
        if (pth_write(socket_fd, &data, data.length) < 0) {
          perror("pth_write");
        }
      } else {
        print("Unrecognised IP packet\n");
      }
    } else if (proto == ETH_P_IPV6) {
      print("IPv6 packet ignored\n");
    } else {
      print("Unrecognised proto type 0x%04X\n", proto);
    }
  }
  return NULL;
}

void *send_heartbeat(void *arg) {
  int socket_fd = (int)(size_t)arg;
  while (1) {
    print("Sending heartbeat\n");
    struct Msg heartbeat = {.type = 104, .length = HEADER_LEN};
    if (pth_write(socket_fd, &heartbeat, heartbeat.length) < 0) {
      perror("pth_write");
      break;
    }
    pth_nap(pth_time(20, 0));
  }
  return NULL;
}

void *connect_server(void *arg) {
  struct sockaddr_in6 addr;
  int socket_fd = socket(AF_INET6, SOCK_STREAM, 0);
  if (socket_fd < 0) {
    perror("error creating socket");
    return NULL;
  }
  bzero(&addr, sizeof(sockaddr_in6));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(5678);

  inet_pton(AF_INET6, server_addr, (struct sockaddr *)&addr.sin6_addr);
  if (pth_connect(socket_fd, (struct sockaddr *)&addr, sizeof(sockaddr_in6)) <
      0) {
    perror("failed to connect to server");
    return NULL;
  }

  struct Msg handshake = {.type = 100, .length = HEADER_LEN};
  if (pth_write(socket_fd, &handshake, handshake.length) < 0) {
    perror("pth_write");
    return NULL;
  }

  pth_attr_t attr;
  attr = pth_attr_new();

  pth_attr_set(attr, PTH_ATTR_NAME, "tun_read");
  pth_t tun = pth_spawn(attr, tun_read, (void *)(size_t)socket_fd);

  pth_attr_set(attr, PTH_ATTR_NAME, "server_read");
  pth_t server = pth_spawn(attr, server_read, (void *)(size_t)socket_fd);

  pth_attr_set(attr, PTH_ATTR_NAME, "send_heartbeat");
  pth_t send = pth_spawn(attr, send_heartbeat, (void *)(size_t)socket_fd);

  pth_attr_destroy(attr);

  pth_join(tun, NULL);
  pth_join(server, NULL);
  pth_join(send, NULL);

  return NULL;
}

int main(int argc, char **argv) {
  if (argc > 1) {
    // unsafe
    strcpy(server_addr, argv[1]);
  }
  pth_init();

  tun_fd = tun_alloc(tun_name);
  run_cmd("ip netns add %s", tun_name);
  run_cmd("ip link set dev %s netns %s", tun_name, tun_name);
  run_cmd("ip -n %s link set dev %s mtu %d", tun_name, tun_name,
          1500 - HEADER_LEN);
  run_cmd("ip -n %s link set dev %s up", tun_name, tun_name);

  pth_attr_t attr;
  attr = pth_attr_new();
  pth_attr_set(attr, PTH_ATTR_NAME, "connect_server");
  pth_t thread = pth_spawn(attr, connect_server, NULL);
  pth_attr_destroy(attr);

  pth_join(thread, NULL);

  return 0;
}
