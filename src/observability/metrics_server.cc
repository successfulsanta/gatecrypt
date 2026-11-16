#include "observability/metrics_server.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <thread>

namespace gatecrypt {

struct MetricsServer::Impl {
  int listen_fd = -1;
  std::atomic<bool> running{false};
  std::thread thread;
};

MetricsServer::MetricsServer(uint16_t port, std::function<std::string()> render,
                             std::function<bool()> ready)
    : port_(port), render_(render), ready_(ready), impl_(new Impl()) {}
MetricsServer::~MetricsServer() {
  Stop();
  delete impl_;
}

bool MetricsServer::Start(std::string& err) {
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    err = "metrics socket";
    return false;
  }
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons(port_);
  a.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(fd, (sockaddr*)&a, sizeof(a)) < 0 || listen(fd, 16) < 0) {
    err = "metrics bind/listen";
    close(fd);
    return false;
  }
  impl_->listen_fd = fd;
  impl_->running.store(true);
  impl_->thread = std::thread([this] {
    int lfd = impl_->listen_fd;
    while (impl_->running.load()) {
      sockaddr_in c{};
      socklen_t sl = sizeof(c);
      int fd2 = accept4(lfd, (sockaddr*)&c, &sl, SOCK_CLOEXEC);
      if (fd2 < 0) {
        if (errno == EINTR) continue;
        if (!impl_->running.load()) break;
        continue;
      }
      char req[1024];
      ssize_t r = recv(fd2, req, sizeof(req) - 1, 0);
      std::string path = "/metrics";
      if (r > 0) {
        req[r] = 0;
        std::string rs(req, (size_t)r);
        auto p1 = rs.find(' ');
        auto p2 = rs.find(' ', p1 + 1);
        if (p1 != std::string::npos && p2 != std::string::npos)
          path = rs.substr(p1 + 1, p2 - p1 - 1);
      }
      std::string body;
      std::string code = "200 OK";
      if (path == "/metrics") {
        body = render_();
      } else if (path == "/healthz") {
        body = "ok\n";
      } else if (path == "/readyz") {
        if (ready_()) {
          body = "ready\n";
        } else {
          code = "503 Unavailable";
          body = "not-ready\n";
        }
      } else {
        code = "404 Not Found";
        body = "not found\n";
      }
      std::string resp = "HTTP/1.0 " + code + "\r\nContent-Type: text/plain\r\nContent-Length: " +
                         std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
      send(fd2, resp.data(), resp.size(), MSG_NOSIGNAL);
      close(fd2);
    }
  });
  return true;
}

void MetricsServer::Stop() {
  if (!impl_->running.exchange(false)) return;
  if (impl_->listen_fd >= 0) {
    shutdown(impl_->listen_fd, SHUT_RDWR);
    close(impl_->listen_fd);
    impl_->listen_fd = -1;
  }
  if (impl_->thread.joinable()) {
    if (impl_->thread.get_id() != std::this_thread::get_id())
      impl_->thread.join();
    else
      impl_->thread.detach();
  }
}

bool DropPrivileges(const std::string& user, std::string& err) {
  if (user.empty()) return true;
  struct passwd* pw = getpwnam(user.c_str());
  if (!pw) {
    err = "unknown user: " + user;
    return false;
  }
  if (setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) {
    err = "setuid/setgid failed";
    return false;
  }
  return true;
}

}  // namespace gatecrypt
