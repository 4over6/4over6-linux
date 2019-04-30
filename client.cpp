#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <uv.h>
#include <vector>

#define print(fmt, args...)                                                    \
  printf("DEBUG: %s:%d:%s(): " fmt, __FILE__, __LINE__, __func__, ##args)

char server[1024] = "2402:f000:1:4417::900";
char tun_name[IFNAMSIZ] = "4over6";
uv_loop_t *loop;
int tun_fd;
uv_stream_t *tcp_stream;
uv_poll_t poll;
uv_timer_t timer;
uv_connect_t tcp_connect;
uv_tcp_t tcp;
std::vector<uint8_t> recv_buffer;

struct Msg {
  uint32_t length;
  uint8_t type;
  uint8_t data[4096];
};

const static int HEADER_LEN = sizeof(uint32_t) + sizeof(uint8_t);

void uv_error(const char *s, int err) {
  print("%s: %s\n", s, uv_strerror(err));
}

int run_cmd(const char *cmd, ...) {
  va_list ap;
  char buf[1024];
  va_start(ap, cmd);
  vsnprintf(buf, sizeof(buf), cmd, ap);
  va_end(ap);
  return system(buf);
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
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
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

void on_write(uv_write_t *req, int status) {
  if (status) {
    uv_error("Got error upon writing", status);
    return;
  }
}

void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  buf->base = (char *)malloc(suggested_size);
  buf->len = suggested_size;
}

void on_remote_data(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
  if (nread < 0) {
    if (nread == UV_EOF) {
      print("Server closed the connection, exiting.");
      exit(0);
    } else {
      uv_error("Got error when reading", nread);
    }
    return;
  }

  recv_buffer.insert(recv_buffer.end(), buf->base, buf->base + nread);
  if (buf->base)
    free(buf->base);

  struct Msg *msg;
  while (msg = (struct Msg *)recv_buffer.data(),
         recv_buffer.size() >= sizeof(uint32_t) &&
             msg->length <= recv_buffer.size()) {
    if (msg->type == 101) {
      // got ip
      uint8_t *p = msg->data, *begin = msg->data,
              *end = msg->data + msg->length - HEADER_LEN;
      int count = 0;
      char data[5][32];
      while (p <= end) {
        if (p == end || *p == ' ') {
          if (count < 5) {
            memcpy(data[count], begin, p - begin);
            data[count][p - begin] = '\0';
            count++;
          }
          begin = p + 1;
        }
        p++;
      }
      if (count >= 1) {
        print("Got ip addr %s\n", data[0]);
        run_cmd("ip -n %s a add local %s/32 dev %s", tun_name, data[0],
                tun_name);
      }
      if (count >= 2) {
        print("Got ip route %s\n", data[1]);
        run_cmd("ip -n %s r add %s/0 dev %s", tun_name, data[1], tun_name);
      }
      if (count >= 3) {
        print("Got dns1 %s\n", data[2]);
      }
      if (count >= 4) {
        print("Got dns2 %s\n", data[3]);
      }
      if (count >= 5) {
        print("Got dns3 %s\n", data[4]);
      }
    } else if (msg->type == 103) {
      // got data response
      size_t length = msg->length - HEADER_LEN;
      print("Got data response of length %ld\n", length);
      write(tun_fd, msg->data, length);
    } else if (msg->type == 104) {
      print("Got heartbeat from server\n");
    } else {
      print("Unrecognized type: %d\n", msg->type);
    }

    recv_buffer.erase(recv_buffer.begin(), recv_buffer.begin() + msg->length);
  }

  uv_read_start(handle, alloc_cb, on_remote_data);
}

void on_heartbeat_timer(uv_timer_t *handle) {
  if (tcp_stream) {
    print("Sending heartbeat\n");
    struct Msg heartbeat = {.type = 104, .length = HEADER_LEN};
    uv_buf_t buf = uv_buf_init((char *)&heartbeat, heartbeat.length);
    uv_write_t write_req;
    uv_write(&write_req, tcp_stream, &buf, 1, on_write);
  }
}

void on_tun_data(uv_poll_t *handle, int status, int events) {
  uint8_t buf[4096];
  size_t max_len = sizeof(buf);
  ssize_t len = read(tun_fd, buf, max_len);
  if (tcp_stream) {
    if (len >= sizeof(struct iphdr)) {
      struct iphdr *hdr = (struct iphdr *)buf;
      if (hdr->version == 4) {
        struct Msg data = {.type = 102};
        memcpy(data.data, buf, len);
        data.length = len + HEADER_LEN;
        uv_buf_t buffer = uv_buf_init((char *)&data, len + HEADER_LEN);
        uv_write_t write_req;
        uv_write(&write_req, tcp_stream, &buffer, 1, on_write);
        print("IP len in header: %d\n", (int)ntohs(hdr->tot_len));
        print("Got data of size %ld from tun and sent to server\n", len);
      } else if (hdr->version == 6) {
        print("Ignoring IPv6 packet\n");
      } else {
        print("Unrecognized IP packet with version %x\n", hdr->version);
      }
    }
  } else {
    print("Got data of size %ld from tun and but server not connected\n", len);
  }
}

void on_server_connected(uv_connect_t *req, int status) {
  if (status < 0) {
    uv_error("Failed to initiate tcp connection", status);
    return;
  }
  tcp_stream = req->handle;

  print("Connected to server\n");

  uv_read_start(req->handle, alloc_cb, on_remote_data);

  struct Msg ask_for_addr = {.type = 100, .length = HEADER_LEN};
  uv_buf_t buf = uv_buf_init((char *)&ask_for_addr, ask_for_addr.length);
  uv_write_t write_req;
  uv_write(&write_req, tcp_stream, &buf, 1, on_write);

  uv_timer_init(loop, &timer);
  uv_timer_start(&timer, on_heartbeat_timer, 1000, 20 * 1000);

  uv_poll_init(loop, &poll, tun_fd);
  uv_poll_start(&poll, UV_READABLE, on_tun_data);
}

int main(int argc, char **argv) {
  int err;
  if (argc > 1) {
    // unsafe
    strcpy(server, argv[1]);
  }
  loop = uv_default_loop();

  tun_fd = tun_alloc(tun_name);
  run_cmd("ip netns add %s", tun_name);
  run_cmd("ip link set dev %s netns %s", tun_name, tun_name);
  run_cmd("ip -n %s link set dev %s mtu %d", tun_name, tun_name,
          1500 - HEADER_LEN);
  run_cmd("ip -n %s link set dev %s up", tun_name, tun_name);

  struct sockaddr_in6 addr;
  uv_ip6_addr(server, 5678, &addr);

  uv_tcp_init(loop, &tcp);
  if ((err = uv_tcp_connect(&tcp_connect, &tcp, (struct sockaddr *)&addr,
                            on_server_connected)) < 0) {
    uv_error("Failed to initiate connection to server", err);
  }

  return uv_run(loop, UV_RUN_DEFAULT);
}
