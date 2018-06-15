#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
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

const char *server = "2402:f000:1:4417::900";
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

int run_cmd(const char *cmd, ...) {
  va_list ap;
  char buf[1024];
  va_start(ap, cmd);
  vsnprintf(buf, sizeof(buf), cmd, ap);
  va_end(ap);
  printf("$ %s\n", buf);
  return system(buf);
}

int tun_alloc(char *dev) {
  struct ifreq ifr = {0};
  int fd, err;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    fprintf(stderr, "Cannot open TUN/TAP dev");
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
    fprintf(stderr, "ERR: Could not ioctl tun: %s\n", strerror(errno));
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);
  return fd;
}

void on_write(uv_write_t *req, int status) {
  if (status) {
    fprintf(stderr, "uv_write error\n");
    return;
  }
}

void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  buf->base = (char *)malloc(suggested_size);
  buf->len = suggested_size;
}

void on_data_received(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
  if (nread < 0) {
    printf("Got error upon reading\n");
    return;
  }
  recv_buffer.insert(recv_buffer.end(), buf->base, buf->base + nread);
  struct Msg *msg = (struct Msg *)recv_buffer.data();
  if (msg->length <= recv_buffer.size()) {
    printf("Received from server: len %d, type %d\n", msg->length, msg->type);
    if (msg->type == 101) {
      // got ip
      uint8_t *p = msg->data, *begin = msg->data,
              *end =
                  msg->data + msg->length - sizeof(uint32_t) - sizeof(uint8_t);
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
        printf("Got ip addr %s\n", data[0]);
        run_cmd("ip a add local %s/32 dev 4over6", data[0]);
      }
      if (count >= 2) {
        printf("Got ip route %s\n", data[1]);
        run_cmd("ip r add %s/0 dev 4over6", data[1]);
      }
      if (count >= 3) {
        printf("Got dns1 %s\n", data[2]);
      }
      if (count >= 4) {
        printf("Got dns2 %s\n", data[3]);
      }
      if (count >= 5) {
        printf("Got dns3 %s\n", data[4]);
      }
    } else if (msg->type == 103) {
      // got data response
      size_t length = msg->length - sizeof(uint32_t) - sizeof(uint8_t);
      printf("Got data response of length %ld\n", length);
      write(tun_fd, msg->data, length);
    }

    recv_buffer.erase(recv_buffer.begin(), recv_buffer.begin() + msg->length);
  }

  uv_read_start(handle, alloc_cb, on_data_received);
}

void on_timer(uv_timer_t *handle) {
  if (tcp_stream) {
    printf("Sending heartbeat\n");
    struct Msg heartbeat = {.type = 104, .length = sizeof(int) + sizeof(char)};
    uv_buf_t buf = uv_buf_init((char *)&heartbeat, heartbeat.length);
    uv_write_t write_req;
    uv_write(&write_req, tcp_stream, &buf, 1, on_write);
  }
}

void on_tun_data(uv_poll_t *handle, int status, int events) {
  uint8_t buf[4096];
  size_t max_len = sizeof(buf);
  ssize_t len = read(tun_fd, buf, max_len);
  if (len > 0) {
    if (tcp_stream) {
      struct Msg data = {.type = 102};
      memcpy(data.data, buf, len);
      data.length = len + sizeof(uint32_t) + sizeof(uint8_t);
      uv_buf_t buffer = uv_buf_init((char *)&data, data.length);
      uv_write_t write_req;
      uv_write(&write_req, tcp_stream, &buffer, 1, on_write);
      printf("Got data of size %ld from tun and sent to server\n", len);
    } else {
      printf("Got data of size %ld from tun and but server not connected\n",
             len);
    }
  }
}

void on_server_connect(uv_connect_t *req, int status) {
  if (status == -1) {
    fprintf(stderr, "Error tcp connection");
    return;
  }
  uv_stream_t *tcp = req->handle;
  tcp_stream = tcp;

  printf("Connected to server\n");

  uv_read_start(req->handle, alloc_cb, on_data_received);

  struct Msg ask_for_addr = {.type = 100, .length = sizeof(int) + sizeof(char)};
  uv_buf_t buf = uv_buf_init((char *)&ask_for_addr, ask_for_addr.length);
  uv_write_t write_req;
  uv_write(&write_req, tcp, &buf, 1, on_write);

  uv_timer_init(loop, &timer);
  uv_timer_start(&timer, on_timer, 0, 20 * 1000);

  uv_poll_init(loop, &poll, tun_fd);
  uv_poll_start(&poll, UV_READABLE, on_tun_data);
}

int main() {
  loop = uv_default_loop();

  char tun_name[IFNAMSIZ] = "4over6";
  tun_fd = tun_alloc(tun_name);
  run_cmd("ip link set dev %s up", tun_name);
  run_cmd("sleep 0.5");

  struct sockaddr_in6 addr;
  uv_ip6_addr(server, 5678, &addr);

  uv_tcp_init(loop, &tcp);
  uv_tcp_connect(&tcp_connect, &tcp, (struct sockaddr *)&addr,
                 on_server_connect);

  return uv_run(loop, UV_RUN_DEFAULT);
}
