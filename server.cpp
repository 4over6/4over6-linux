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

char tun_name[IFNAMSIZ] = "4over6server";
uv_loop_t *loop;
const static int TUN_FDS = 10;
int tun_fds[TUN_FDS];
uv_poll_t polls[TUN_FDS];
uv_timer_t timer;
uv_connect_t tcp_connect;
uv_tcp_t tcp_server;
uv_tcp_t tcp_client;
std::vector<uint8_t> recv_buffer;

typedef struct write_req_t {
  uv_write_t req;
  uv_buf_t buf;
} write_req_t;

struct Msg
{
  uint32_t length;
  uint8_t type;
  uint8_t data[4096];
};

const static int HEADER_LEN = sizeof(uint32_t) + sizeof(uint8_t);

void uv_error(const char *s, int err) { printf("%s: %s", s, uv_strerror(err)); }

int run_cmd(const char *cmd, ...) {
  va_list ap;
  char buf[1024];
  va_start(ap, cmd);
  vsnprintf(buf, sizeof(buf), cmd, ap);
  va_end(ap);
  return system(buf);
}

void tun_alloc(char *dev) {
  struct ifreq ifr = {0};

  /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
   *        IFF_TAP   - TAP device
   *
   *        IFF_NO_PI - Do not provide packet information
   */
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  for (int i = 0; i < TUN_FDS; i++) {
    if ((tun_fds[i] = open("/dev/net/tun", O_RDWR)) < 0) {
      perror("Cannot open TUN dev");
      exit(1);
    }
    if (ioctl(tun_fds[i], TUNSETIFF, (void *)&ifr) < 0) {
      perror("Cannot initialize TUN device");
      exit(1);
    }
  }

  strcpy(dev, ifr.ifr_name);
  return;
}

void on_write(uv_write_t *req, int status) {
  if (status) {
    uv_error("Got error upon writing", status);
    return;
  }
  write_req_t *wr = (write_req_t *)req;
  free(wr->buf.base);
  free(wr);
}

void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  buf->base = (char *)malloc(suggested_size);
  buf->len = suggested_size;
}

void on_remote_data(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
  if (nread < 0) {
    uv_error("Got error when reading", nread);
    return;
  }

  recv_buffer.insert(recv_buffer.end(), buf->base, buf->base + nread);
  if (buf->base)
    free(buf->base);

  struct Msg *msg;
  while (msg = (struct Msg *)recv_buffer.data(),
         recv_buffer.size() >= sizeof(uint32_t) &&
             msg->length <= recv_buffer.size()) {
    if (msg->type == 100) {
      char result[] = "13.8.0.2 0.0.0.0 101.6.6.6 166.111.8.28 166.111.8.29";

      write_req_t *wr = (write_req_t *)malloc(sizeof(write_req_t));
      size_t msg_length = strlen(result) + HEADER_LEN;
      wr->buf = uv_buf_init((char *)malloc(msg_length), msg_length);

      struct Msg *new_msg = (struct Msg *)wr->buf.base;
      new_msg->type = 101;
      new_msg->length = msg_length;
      memcpy(new_msg->data, result, strlen(result));
      uv_write((uv_write_t *)wr, (uv_stream_t *)&tcp_client, &wr->buf, 1, on_write);
    } else if (msg->type == 102) {
      // got data request
      size_t length = msg->length - HEADER_LEN;
      printf("Got data response of length %ld\n", length);
      static int index = 0;
      write(tun_fds[(index++) % TUN_FDS], msg->data, length);
    } else if (msg->type == 104) {
      printf("Got heartbeat from client\n");
    } else {
      printf("Unrecognized type: %d\n", msg->type);
    }

    recv_buffer.erase(recv_buffer.begin(), recv_buffer.begin() + msg->length);
  }

  uv_read_start(handle, alloc_cb, on_remote_data);
}

void on_heartbeat_timer(uv_timer_t *handle) {
  /*
if (tcp_stream) {
  printf("Sending heartbeat\n");
  struct Msg heartbeat = {.type = 104, .length = HEADER_LEN};
  uv_buf_t buf = uv_buf_init((char *)&heartbeat, heartbeat.length);
  uv_write_t write_req;
  uv_write(&write_req, tcp_stream, &buf, 1, on_write);
}
*/
}

void on_tun_data(uv_poll_t *handle, int status, int events) {
  uint8_t buf[4096];
  size_t max_len = sizeof(buf);
  int tun_fd = (int)(size_t)handle->data;
  ssize_t len = read(tun_fd, buf, max_len);
  if (len >= sizeof(struct iphdr)) {
    struct iphdr *hdr = (struct iphdr *)buf;
    if (hdr->version == 4) {
      write_req_t *wr = (write_req_t *)malloc(sizeof(write_req_t));
      size_t msg_length = len + HEADER_LEN;
      wr->buf = uv_buf_init((char *)malloc(msg_length), msg_length);

      struct Msg *new_msg = (struct Msg *)wr->buf.base;
      new_msg->type = 103;
      new_msg->length = msg_length;
      memcpy(new_msg->data, buf, len);
      uv_write((uv_write_t *)wr, (uv_stream_t *)&tcp_client, &wr->buf, 1, on_write);

      printf("IP len in header: %d\n", (int)ntohs(hdr->tot_len));
      printf("Got data of size %ld from tun and sent to client\n", len);
    } else if (hdr->version == 6) {
      printf("Ignoring IPv6 packet\n");
    } else {
      printf("Unrecognized IP packet with version %x\n", hdr->version);
    }
  }
}

void on_client_connected(uv_stream_t *req, int status) {
  if (status < 0) {
    uv_error("Failed to initiate tcp connection", status);
    return;
  }
  uv_tcp_init(loop, &tcp_client);
  uv_accept(req, (uv_stream_t *)&tcp_client);

  for (int i = 0; i < TUN_FDS; i++) {
    uv_poll_init(loop, &polls[i], tun_fds[i]);
    polls[i].data = (void *)(size_t)tun_fds[i];
    uv_poll_start(&polls[i], UV_READABLE, on_tun_data);
  }

  uv_read_start((uv_stream_t *)&tcp_client, alloc_cb, on_remote_data);
}

int main() {
  int err;
  loop = uv_default_loop();

  tun_alloc(tun_name);
  run_cmd("ip link set dev %s up", tun_name);
  run_cmd("ip link set dev %s mtu %d", tun_name, 1500 - HEADER_LEN);
  run_cmd("sleep 0.5");
  run_cmd("ip a add 13.8.0.1/24 dev %s", tun_name);

  struct sockaddr_in6 addr;
  uv_ip6_addr("::", 5678, &addr);

  uv_tcp_init(loop, &tcp_server);
  uv_tcp_bind(&tcp_server, (struct sockaddr *)&addr, 0);
  if ((err = uv_listen((uv_stream_t *)&tcp_server, 10, on_client_connected)) <
      0) {
    uv_error("Failed to initiate connection to server", err);
  }

  return uv_run(loop, UV_RUN_DEFAULT);
}
