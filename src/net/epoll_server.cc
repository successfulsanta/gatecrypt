#include "net/epoll_server.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#include "observability/logger.h"
#include "protocol/framing.h"

namespace gatecrypt {
namespace {

int64_t NowMs() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

[[maybe_unused]] bool SetNonblock(int fd) {
  int f = fcntl(fd, F_GETFL, 0);
  if (f < 0) return false;
  return fcntl(fd, F_SETFL, f | O_NONBLOCK) == 0;
}

struct TokenBucket {
  double tokens = 1000;
  int64_t last_ms = 0;
};

struct Conn {
  int fd = -1;
  std::string ip;
  std::vector<uint8_t> in;
  std::vector<uint8_t> out;
  int64_t last_active_ms = 0;
  int64_t created_ms = 0;
  bool header_done = false;
};

}  // namespace

struct EpollServer::Impl {
  const Config& cfg;
  VerifyHandler handler;
  int listen_fd = -1;
  int epoll_fd = -1;
  std::atomic<bool> running{false};
  std::thread thread;
  mutable std::mutex mu;
  std::unordered_map<int, Conn> conns;
  std::unordered_map<std::string, TokenBucket> buckets;
  ServerStats stats;

  Impl(const Config& c, VerifyHandler h) : cfg(c), handler(h) {}
};

EpollServer::EpollServer(const Config& cfg, VerifyHandler handler)
    : cfg_(cfg), handler_(handler), impl_(new Impl(cfg, handler)) {}

EpollServer::~EpollServer() {
  Stop();
  delete impl_;
}

ServerStats EpollServer::stats() const {
  std::lock_guard<std::mutex> lk(impl_->mu);
  return impl_->stats;
}

bool EpollServer::Start(std::string& err) {
  int lfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (lfd < 0) {
    err = "socket";
    return false;
  }
  int one = 1;
  setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_REUSEPORT
  setsockopt(lfd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif
  setsockopt(lfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(cfg_.port);
  if (bind(lfd, (sockaddr*)&addr, sizeof(addr)) < 0) {
    err = "bind port " + std::to_string(cfg_.port);
    close(lfd);
    return false;
  }
  if (listen(lfd, 1024) < 0) {
    err = "listen";
    close(lfd);
    return false;
  }
  int efd = epoll_create1(EPOLL_CLOEXEC);
  if (efd < 0) {
    err = "epoll_create1";
    close(lfd);
    return false;
  }
  epoll_event ev{};
  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = lfd;
  if (epoll_ctl(efd, EPOLL_CTL_ADD, lfd, &ev) < 0) {
    err = "epoll_ctl listen";
    close(lfd);
    close(efd);
    return false;
  }
  impl_->listen_fd = lfd;
  impl_->epoll_fd = efd;
  impl_->running.store(true);
  impl_->thread = std::thread([this] { Run(); });
  GC_LOG_INFO("net", "listening on port " + std::to_string(cfg_.port));
  return true;
}

void EpollServer::Stop() {
  if (!impl_->running.exchange(false)) return;
  if (impl_->epoll_fd >= 0) {
    close(impl_->epoll_fd);
    impl_->epoll_fd = -1;
  }
  if (impl_->listen_fd >= 0) {
    // shutdown to wake epoll
    shutdown(impl_->listen_fd, SHUT_RDWR);
  }
  if (impl_->thread.joinable()) {
    // Detach-safety: if Stop called from IO thread itself, detach.
    if (impl_->thread.get_id() == std::this_thread::get_id())
      impl_->thread.detach();
    else
      impl_->thread.join();
  }
  std::lock_guard<std::mutex> lk(impl_->mu);
  for (auto& kv : impl_->conns) close(kv.second.fd);
  impl_->conns.clear();
  if (impl_->listen_fd >= 0) {
    close(impl_->listen_fd);
    impl_->listen_fd = -1;
  }
}

static bool AllowRequest(TokenBucket& b, int64_t now, double rate, double burst) {
  if (b.last_ms == 0) {
    b.last_ms = now;
    b.tokens = burst;
  }
  double dt = (now - b.last_ms) / 1000.0;
  b.tokens = std::min(burst, b.tokens + dt * rate);
  b.last_ms = now;
  if (b.tokens < 1.0) return false;
  b.tokens -= 1.0;
  return true;
}

void EpollServer::Run() {
  constexpr int kMaxEvents = 256;
  epoll_event events[kMaxEvents];
  int efd = impl_->epoll_fd;
  while (impl_->running.load()) {
    int n = epoll_wait(efd, events, kMaxEvents, 100);
    if (n < 0) {
      if (errno == EINTR) continue;
      break;  // epoll closed during Stop
    }
    int64_t now = NowMs();
    for (int i = 0; i < n; ++i) {
      int fd = events[i].data.fd;
      uint32_t ev = events[i].events;
      if (fd == impl_->listen_fd) {
        // Accept all pending (edge-triggered drain).
        while (true) {
          sockaddr_in cli{};
          socklen_t sl = sizeof(cli);
          int cfd = accept4(impl_->listen_fd, (sockaddr*)&cli, &sl, SOCK_NONBLOCK | SOCK_CLOEXEC);
          if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            break;
          }
          int one = 1;
          setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
          char ipb[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, &cli.sin_addr, ipb, sizeof(ipb));
          std::string ip = ipb;
          std::lock_guard<std::mutex> lk(impl_->mu);
          if ((int)impl_->conns.size() >= impl_->cfg.max_connections) {
            impl_->stats.rejected_conn_limit++;
            close(cfd);
            continue;
          }
          // Per-IP connection cap.
          int ipcount = 0;
          for (auto& kv : impl_->conns)
            if (kv.second.ip == ip) ipcount++;
          if (ipcount >= impl_->cfg.max_conn_per_ip) {
            impl_->stats.rejected_conn_limit++;
            close(cfd);
            continue;
          }
          // Rate limit.
          TokenBucket& b = impl_->buckets[ip];
          if (!AllowRequest(b, now, impl_->cfg.rate_per_sec, impl_->cfg.rate_burst)) {
            impl_->stats.rate_limited++;
            close(cfd);
            continue;
          }
          epoll_event cev{};
          cev.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP;
          cev.data.fd = cfd;
          if (epoll_ctl(efd, EPOLL_CTL_ADD, cfd, &cev) < 0) {
            close(cfd);
            continue;
          }
          Conn c;
          c.fd = cfd;
          c.ip = ip;
          c.last_active_ms = now;
          c.created_ms = now;
          impl_->conns[cfd] = std::move(c);
          impl_->stats.accepted++;
        }
        continue;
      }
      if (ev & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
        std::lock_guard<std::mutex> lk(impl_->mu);
        auto it = impl_->conns.find(fd);
        if (it != impl_->conns.end()) {
          epoll_ctl(efd, EPOLL_CTL_DEL, fd, nullptr);
          close(fd);
          impl_->conns.erase(it);
        }
        continue;
      }
      // Read drain (edge-triggered: read until EAGAIN).
      std::lock_guard<std::mutex> lk(impl_->mu);
      auto it = impl_->conns.find(fd);
      if (it == impl_->conns.end()) continue;
      Conn& c = it->second;
      c.last_active_ms = now;
      if (ev & EPOLLIN) {
        bool closed = false;
        while (true) {
          uint8_t tmp[65536];
          ssize_t r = recv(fd, tmp, sizeof(tmp), 0);
          if (r > 0) {
            c.in.insert(c.in.end(), tmp, tmp + r);
          } else if (r == 0) {
            closed = true;
            break;
          } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            closed = true;
            break;
          }
        }
        if (closed) {
          epoll_ctl(efd, EPOLL_CTL_DEL, fd, nullptr);
          close(fd);
          impl_->conns.erase(it);
          continue;
        }
        // Idle / slowloris: header must arrive within header_timeout_ms.
        if (!c.header_done && (now - c.created_ms) > (int64_t)impl_->cfg.header_timeout_ms &&
            c.in.size() < kHeaderBytes) {
          epoll_ctl(efd, EPOLL_CTL_DEL, fd, nullptr);
          close(fd);
          impl_->conns.erase(it);
          continue;
        }
        if ((now - c.last_active_ms) > (int64_t)impl_->cfg.idle_timeout_ms) {
          // last_active just updated; check creation-based idle instead
        }
        // Parse complete frames.
        while (c.in.size() >= kHeaderBytes) {
          uint32_t plen = ((uint32_t)c.in[8] << 24) | ((uint32_t)c.in[9] << 16) |
                          ((uint32_t)c.in[10] << 8) | (uint32_t)c.in[11];
          if (plen > impl_->cfg.max_frame_bytes) {
            auto erf = EncodeFrame(MsgType::Error, EncodeVerifyResponse(VerifyCode::Malformed));
            c.out.insert(c.out.end(), erf.begin(), erf.end());
            c.in.clear();
            break;
          }
          if (c.in.size() < kHeaderBytes + plen) break;
          c.header_done = true;
          std::vector<uint8_t> frame(c.in.begin(), c.in.begin() + kHeaderBytes + plen);
          c.in.erase(c.in.begin(), c.in.begin() + kHeaderBytes + plen);
          Frame fr;
          std::string perr;
          if (!DecodeFrame(frame.data(), frame.size(), fr, perr, impl_->cfg.max_frame_bytes)) {
            auto erf = EncodeFrame(MsgType::Error, EncodeVerifyResponse(VerifyCode::Malformed));
            c.out.insert(c.out.end(), erf.begin(), erf.end());
            continue;
          }
          std::vector<uint8_t> resp;
          if (fr.type == MsgType::VerifyReq) {
            resp = impl_->handler(fr.payload);
            // handler returns full frame bytes
          } else if (fr.type == MsgType::NonceReq) {
            // Nonce issuance handled by handler too (payload empty).
            resp = impl_->handler(fr.payload);
          } else {
            resp = EncodeFrame(MsgType::Error, EncodeVerifyResponse(VerifyCode::Malformed));
          }
          c.out.insert(c.out.end(), resp.begin(), resp.end());
        }
        // Enforce idle timeout sweep (cheap: per readable conn).
        if ((now - c.last_active_ms) > (int64_t)impl_->cfg.idle_timeout_ms && c.in.empty() &&
            c.out.empty()) {
          epoll_ctl(efd, EPOLL_CTL_DEL, fd, nullptr);
          close(fd);
          impl_->conns.erase(it);
          continue;
        }
      }
      if (ev & EPOLLOUT) {
        // Flush pending output (edge-triggered: write until EAGAIN).
        auto it2 = impl_->conns.find(fd);
        if (it2 == impl_->conns.end()) continue;
        Conn& c2 = it2->second;
        while (!c2.out.empty()) {
          ssize_t w = send(fd, c2.out.data(), c2.out.size(), MSG_NOSIGNAL);
          if (w > 0) {
            c2.out.erase(c2.out.begin(), c2.out.begin() + w);
          } else if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            epoll_ctl(efd, EPOLL_CTL_DEL, fd, nullptr);
            close(fd);
            impl_->conns.erase(it2);
            break;
          }
        }
      }
    }
    // Periodic idle sweep every loop (cheap when idle due to 100ms timeout).
    {
      std::lock_guard<std::mutex> lk(impl_->mu);
      for (auto it = impl_->conns.begin(); it != impl_->conns.end();) {
        if ((now - it->second.last_active_ms) > (int64_t)impl_->cfg.idle_timeout_ms) {
          epoll_ctl(efd, EPOLL_CTL_DEL, it->first, nullptr);
          close(it->first);
          it = impl_->conns.erase(it);
        } else {
          ++it;
        }
      }
    }
  }
}

}  // namespace gatecrypt
