#include <Arduino.h>
#include <IPAddress.h>
#include <Preferences.h>
#include <general_fun.h>
#include <lwip/inet.h>
#include <lwip/sockets.h>
#include <ssh.h>

#ifndef L_HOST
#define L_HOST "localhost"
#endif
#define MAX_CONNS 10
#define DEBUG_ENABLED 1

#if DEBUG_ENABLED
#define DEBUG(__x...) Serial.printf(__x)
#else
#define DEBUG(__x...) do {} while (0)
#endif
String localTargetString;
// the address structure that we will connect to
struct addrinfo s_hints = {.ai_socktype = SOCK_STREAM};
struct addrinfo *s_target;

void libssh_task(void *pvParameters);
int ssh_port = 0;
TaskHandle_t ssh_task_handle = nullptr;
bool ssh_ready = false;
static void error(ssh_session session) {
  fprintf(stderr, "Authentication failed: %s\n", ssh_get_error(session));
}
static int auth_keyfile(ssh_session session, char *keyfile) {
  ssh_key key = nullptr;
  char pubkey[132] = {0}; // +".pub"
  int rc;
  keyfile = "/littlefs/.ssh/id_ed25519";
  snprintf(pubkey, sizeof(pubkey), "%s.pub", keyfile);

  rc = ssh_pki_import_pubkey_file(pubkey, &key);

  if (rc != SSH_OK)
    return SSH_AUTH_DENIED;

  rc = ssh_userauth_try_publickey(session, nullptr, key);

  ssh_key_free(key);

  if (rc != SSH_AUTH_SUCCESS)
    return SSH_AUTH_DENIED;

  rc = ssh_pki_import_privkey_file(keyfile, nullptr, nullptr, nullptr, &key);

  if (rc != SSH_OK)
    return SSH_AUTH_DENIED;

  rc = ssh_userauth_publickey(session, nullptr, key);
  ssh_key_free(key);

  return rc;
}
int authenticate_console(ssh_session session) {
  int rc;
  int method;
  char *banner;

  // Try to authenticate
  rc = ssh_userauth_none(session, nullptr);
  if (rc == SSH_AUTH_ERROR) {
    error(session);
    return rc;
  }

  method = ssh_userauth_list(session, nullptr);
  while (rc != SSH_AUTH_SUCCESS) {
    if (method & SSH_AUTH_METHOD_GSSAPI_MIC) {
      rc = ssh_userauth_gssapi(session);
      if (rc == SSH_AUTH_ERROR) {
        error(session);
        return rc;
      } else if (rc == SSH_AUTH_SUCCESS) {
        break;
      }
    }

    if (method & SSH_AUTH_METHOD_PUBLICKEY) {
      rc = ssh_userauth_publickey_auto(session, nullptr, nullptr);
      if (rc == SSH_AUTH_ERROR) {
        error(session);
        return rc;
      } else if (rc == SSH_AUTH_SUCCESS) {
        break;
      }
    }

    {
      char buffer[128] = {0};
      char *p = nullptr;

      printf("private key filename: \n");

      rc = auth_keyfile(session, buffer);

      if (rc == SSH_AUTH_SUCCESS) {
        break;
      }
      fprintf(stderr, "failed with key\n");
    }
  }

  banner = ssh_get_issue_banner(session);
  if (banner) {
    printf("%s\n", banner);
    SSH_STRING_FREE_CHAR(banner);
  }

  return rc;
}
ssh_session connect_ssh(const char *host, const char *user, int verbosity) {
  ssh_session session;
  int auth = 0;
  session = ssh_new();
  if (session == nullptr) {
    return nullptr;
  }

  if (user != nullptr) {
    if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0) {
      ssh_free(session);
      return nullptr;
    }
  }

  if (ssh_options_set(session, SSH_OPTIONS_HOST, host) < 0) {
    ssh_free(session);
    return nullptr;
  }

  ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
  if (ssh_connect(session)) {
    fprintf(stderr, "Connection failed : %s\n", ssh_get_error(session));
    ssh_disconnect(session);
    ssh_free(session);
    return nullptr;
  }
  int timeout = 60000; // seconds
  ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout);
  int nodelay = 1;
  ssh_options_set(session, SSH_OPTIONS_NODELAY, &nodelay);

  auth = authenticate_console(session);
  if (auth == SSH_AUTH_SUCCESS) {
    return session;
  } else if (auth == SSH_AUTH_DENIED) {
    fprintf(stderr, "Authentication failed\n");
  } else {
    fprintf(stderr, "Error while authenticating : %s\n",
            ssh_get_error(session));
  }
  ssh_disconnect(session);
  ssh_free(session);
  return nullptr;
}

bool config_ssh() {
  // Set the SSH port
  xTaskCreate(libssh_task, "libssh_task", 16384, nullptr, 3, &ssh_task_handle);
  return true;
}

class myconn {
private:
  ssh_channel m_remote;
  int m_local; // socket
  time_t m_creation_time;
  time_t m_lasttime;
  bool m_remote_connected;
  bool m_local_connected;
  bool m_shutdown;

public:
  myconn(ssh_channel ch) {
    DEBUG("myconn %p opening\n", this);

    // set up member variables
    m_remote = ch;
    m_lasttime = 0;
    m_remote_connected = true;
    m_local_connected = false;
    bool l_close_remote = true; // assume failure
    m_shutdown = false;

    // connect our socket
    m_local = socket(s_target->ai_family, s_target->ai_socktype,
                     s_target->ai_protocol);
    if (m_local < 0) {
      DEBUG("myconn %p failed to create socket, error %d\n", this, errno);
    } else if (fcntl(m_local, F_SETFL, fcntl(m_local, F_GETFL) | O_NONBLOCK) ==
               -1) {
      DEBUG("myconn %p unable to set socket non blocking, error %d\n", this,
            errno);
      close(m_local);
      m_local = -1;
    } else if (connect(m_local, s_target->ai_addr, s_target->ai_addrlen) == 0) {
      // socket is connected
      DEBUG("myconn %p connected %d\n", this, m_local);
      m_local_connected = true;
      l_close_remote = false;
    } else if ((errno == EAGAIN) || (errno == EINPROGRESS)) {
      // socket is pending connection
      DEBUG("myconn %p waiting for connection to complete %d\n", this, m_local);
      l_close_remote = false;
    } else {
      DEBUG("myconn %p failed to connect, errno %d\n", this, errno);
      // syslogf("onwards failed to connect, errno %d",errno);
      close(m_local);
      m_local = -1;
    }
    if (l_close_remote) {
      closeRemote();
    }
  }
  ~myconn() { DEBUG("myconn %p deleted\n", this); }

  bool isShutdown() { return m_shutdown; }
  bool isLocalConnected() { return m_local_connected; }
  int getFd() { return m_local; }

  void closeRemote() {
    if (m_remote_connected) {
      m_remote_connected = false;
      ssh_channel_send_eof(m_remote);
      ssh_channel_close(m_remote);
    }
  }

  // cleanly tear the connection down
  void doShutdown() {
    DEBUG("myconn %p closing\n", this);
    closeRemote();
    if (m_local_connected) {
      m_local_connected = false;
      int r = close(m_local);
      if (r != 0) {
        DEBUG("myconn %p failed to close, errno %d\n", errno);
      }
      m_local = -1;
      m_shutdown = true;
    }
    // wait for the close to complete before marking as shut down
  }

  void handleRead() {
    DEBUG("myconn %p processing read\n", this);
    uint8_t buf[512];
    int len;
    while (1) {
      len = read(m_local, buf, 512);
      DEBUG("myconn %p read %d bytes\n", this, len);
      if (len > 0) {
        // Serial.write((uint8_t*)data, len);
        if (m_remote_connected) {
          ssh_channel_write(m_remote, buf, len);
        }
      } else if ((len < 0) && (errno == EAGAIN)) {
        // no more data
        break;
      } else {
        // connection closed
        DEBUG("myconn %p read error %d\n", errno);
        doShutdown();
        break;
      }
    }
    m_lasttime = time(nullptr);
  }

  void handleWrite() {
    // writable is only used to detect that the socket connected
    int sockerr;
    socklen_t len = (socklen_t)sizeof(int);
    if (getsockopt(m_local, SOL_SOCKET, SO_ERROR, (void *)(&sockerr), &len) <
        0) {
      DEBUG("myconn %p failed to get socket status, %d\n", this, errno);
      doShutdown();
    } else if (sockerr) {
      DEBUG("myconn %p failed to connect, erno %d\n", sockerr);
      // syslogf("onward connection failed to connect, %d",sockerr);
      doShutdown();
    } else {
      DEBUG("myconn %p connected to %s on port %d \n", this, localTargetString,
            ssh_port);
      m_lasttime = time(nullptr);
      m_local_connected = true;
    }
  }

  void handleError() {
    DEBUG("myconn %p handle error\n", this);
    doShutdown();
  }

  // ssh has some data to tunnel
  bool write(void *data, size_t len) {
    m_lasttime = time(nullptr);
    if (m_local_connected) {
      DEBUG("myconn %p sending %d bytes\n", this, len);
      while (len > 0) {
        int lw = ::write(m_local, data, len);
        if (lw == len) {
          // all written ok
          break;
        } else if (lw > 0) {
          DEBUG("myconn %p only sent %d bytes, errno %d\n", this, lw, errno);
          len -= lw;
          data += lw;
          delay(10);
          // go round the loop again
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
          delay(10);
          // go round the loop again
        } else {
          DEBUG("myconn %p write error %d\n", this, errno);
          return false;
        }
      } // end looping over all data
      return true;
    } else {
      DEBUG("myconn %p cannot send %d bytes", this, len);
      return false;
    }
  }
  bool check_timeout() {
    // can only time out after connected
    if ((m_lasttime != 0) && ((time(nullptr) - m_lasttime) > 60)) {
      DEBUG("myconn %p timed out\n", this);
      return true;
    }
    return false;
  }
  bool checkConnectionTime() {
    time_t current_time = time(NULL);
    time_t connection_duration = current_time - m_creation_time;
    
    if (connection_duration > 10 && !m_local_connected) {
        DEBUG("myconn %p connection attempt timeout after %ld seconds\n", this, connection_duration);
        return true;
    }
    return false;
}

void attemptReconnect() {
    if (m_local_connected) {
        close(m_local);
        m_local_connected = false;
    }
    
    m_local = socket(s_target->ai_family, s_target->ai_socktype, s_target->ai_protocol);
    if (m_local < 0) {
        DEBUG("myconn %p reconnect failed to create socket, error %d\n",this,errno);
        return;
    }
    
    if (fcntl(m_local, F_SETFL, fcntl(m_local, F_GETFL) | O_NONBLOCK) == -1) {
        DEBUG("myconn %p reconnect unable to set socket non blocking, error %d\n",this,errno);
        close(m_local);
        m_local = -1;
        return;
    }
    
    if (connect(m_local, s_target->ai_addr, s_target->ai_addrlen) == 0) {
        DEBUG("myconn %p reconnected %d\n",this,m_local);
        m_local_connected = true;
    } else if ((errno == EAGAIN) || (errno == EINPROGRESS)) {
        DEBUG("myconn %p waiting for reconnection to complete %d\n",this,m_local);
    } else {
        DEBUG("myconn %p failed to reconnect, errno %d\n",this,errno);
        close(m_local);
        m_local = -1;
    }
}
};

void run_tunnel2(ssh_session &session) {

  ssh_channel channel;
  char buffer[256];
  int rbytes, wbytes, total = 0;
  int rc;
  struct timeval tmo;

  // create the reverse tunnel
  rc = ssh_channel_listen_forward(session, nullptr, ssh_port, nullptr);
  if (rc != SSH_OK) {
    // syslogf("Error opening remote port: %s", ssh_get_error(session));
    return;
  }

  // the set of connections
  std::map<ssh_channel, myconn *> conn_list;

  while (ssh_is_connected(session)) {
    int timeout = 0;
    if (conn_list.empty()) {
      timeout = 60000;
    }
    UBaseType_t uxHighWaterMark = uxTaskGetStackHighWaterMark(NULL);
    printf("Mémoire stack libre : %u bytes\n", uxHighWaterMark);
    // do not permit more than max connections
    if (conn_list.size() < MAX_CONNS) {
      DEBUG("Checking for new connections for %d\n", timeout);
      channel = ssh_channel_accept_forward(session, timeout, nullptr);
      if (channel != nullptr) {
        // got incoming connection
        DEBUG("Got new connection channel %p\n", channel);
        conn_list[channel] = new myconn(channel);
      } else if (conn_list.empty()) {
        // no connected channels, go round the loop again
        continue;
      }
    }

    // wait for something to happen
    // TODO use fde to spot errors
    fd_set fde, fdw, fdr;
    int maxfd;
    int k = ssh_get_fd(session);
    DEBUG("ssh fd %d\n", k);
    FD_ZERO(&fde);
    FD_ZERO(&fdr);
    FD_ZERO(&fdw);
    // FD_SET(k, &fde);
    FD_SET(k, &fdr);
    // FD_SET(k, &fdw);
    maxfd = k;
    std::map<ssh_channel, myconn *>::const_iterator j = conn_list.begin();
    while (j != conn_list.end()) {
      k = j->second->getFd();
      if (k >= 0) {
        maxfd = std::max(k, maxfd);
        // FD_SET(k, &fde);
        if (j->second->isLocalConnected()) {
          FD_SET(k, &fdr);
        } else {
          FD_SET(k, &fdw);
        }
      }
      ++j;
    }

    // wait for max 1 sec before checking for timeouts
    tmo.tv_sec = 0;
    tmo.tv_usec = 500000;

    // find the connections with data
    DEBUG("0 maxfd %d\n", maxfd);
    rc = select(maxfd + 1, &fdr, &fdw, &fde, &tmo);
    DEBUG("1 rc %d\n", rc);
    DEBUG("readable: ");
    for (k = 0; k <= maxfd; ++k) {
      if (FD_ISSET(k, &fdr)) {
        DEBUG("%d ", k);
      }
    };
    DEBUG("\n");
    DEBUG("writable: ");
    for (k = 0; k <= maxfd; ++k) {
      if (FD_ISSET(k, &fdw)) {
        DEBUG("%d ", k);
      }
    };
    DEBUG("\n");
    DEBUG("error: ");
    for (k = 0; k <= maxfd; ++k) {
      if (FD_ISSET(k, &fde)) {
        DEBUG("%d ", k);
      }
    };
    DEBUG("\n");

    // has some data come in from the local side
    j = conn_list.begin();
    while (j != conn_list.end()) {
      k = j->second->getFd();
      if (k < 0) {
        // not connected
      } else if (FD_ISSET(k, &fdr)) {
        // fd is readable
        j->second->handleRead();
      } else if (FD_ISSET(k, &fdw)) {
        // fd is readable
        j->second->handleWrite();
      } else if (FD_ISSET(k, &fde)) {
        // fd has errored
        j->second->handleError();
      }
      ++j;
    }

    if (!FD_ISSET(ssh_get_fd(session), &fdr)) {
      // nothing waiting for the ssh side so continue round the loop
      DEBUG("ssh not ready\n");
      // ssh fd is not reliable enough to continue
      // continue;
    } else {
      // TODO is this necessary?
      DEBUG("kick ssh\n");
      ssh_set_fd_toread(session);
    }

    // build list of connections to watch
    // tidy any existing closures
    j = conn_list.begin();

    while (j != conn_list.end()) {
      bool closeChannel = false;
      if (!ssh_channel_is_open(j->first)) {
        // likely local closed on us, async has closed the ssh channel
        // so we are just tidying up here
        DEBUG("Channel %p has closed\n", j->second);
        closeChannel = true;
      } else if (j->second->check_timeout()) {
        // channel has timed out, close it
        DEBUG("Channel %p has timed out\n", j->second);
        closeChannel = true;
      } else if (!j->second->isLocalConnected()) {
        // channel is active but local is not yet connected so skip this time
        // around
        if (j->second->checkConnectionTime()) {
          DEBUG("Channel %p connection timeout\n",j->second);
          closeChannel = true;
      } else {
          DEBUG("Channel %p not connected\n",j->second);
          ++j;
      }
      } else {
        // channel is still active
        // run connection until no more data
        int len;
        while (1) {
          len =
              ssh_channel_read_timeout(j->first, buffer, sizeof(buffer), 0, 0);
          DEBUG("Channel %p read %d\n", j->first, len);
          if (len == -1) {
            // drop out of the loop when not readable
            DEBUG("Error reading channel %p: %s\n", j->second,
                  ssh_get_error(session));
            break;
          } else if (len > 0) {
            // have some data, send to local
            if (!j->second->write(buffer, len)) {
              DEBUG("Write failure on channel %p\n", j->second);
              // error occurred, close the connection
              closeChannel = true;
              break;
            }
          } else if (ssh_channel_is_eof(j->first)) {
            DEBUG("EOF on channel %p\n", j->second);
            closeChannel = true;
            break;
          } else {
            // no data received
            break;
          }
        }
      }
      if (closeChannel) {
        j->second->doShutdown();
        delete j->second;
        ssh_channel_free(j->first);
        conn_list.erase(j++);
      } else {
        ++j;
      }
    } // end of running a connection

  } // end of session still active

  // close local connections
  DEBUG("Session closed, closing %d connections\n", conn_list.size());
  Serial.print("Session closed, closing ");
  Serial.print(conn_list.size());
  std::map<ssh_channel, myconn *>::const_iterator j = conn_list.begin();
  while (j != conn_list.end()) {
    // close everything as required
    j->second->doShutdown();
    ++j;
  }
  delay(1000);
  while (conn_list.begin() != conn_list.end()) {
    // deleting the connection will close the ssh channel
    delete conn_list.begin()->second;
    ssh_channel_free(conn_list.begin()->first);
    conn_list.erase(conn_list.begin());
  }
}

void libssh_task(void *pvParameters) {
  vTaskDelay(5000);
  ssh_session session;
  while (true) {
    libssh_begin();
    int ssh_port;

    // Récupérer le port dans le NVS
    Preferences preferences;
    preferences.begin("ssh", false);
    ssh_port = preferences.getInt("port", 9000);
    preferences.end();
    Serial.print("ssh_port: ");
    Serial.println(ssh_port);

    session = connect_ssh(L_HOST, "ssh", 0);
    if (session == nullptr) {
      Serial.printf("Failed to connect SSH session\n");
      ssh_disconnect(session);
      ssh_free(session);
      ssh_finalize();
      delay(1000);
      continue;
    }
    IPAddress Ip = connexionState.ip;
    Serial.printf("IP: %s\n", Ip.toString().c_str());

    // Stocker la chaîne dans une variable locale persistante
    localTargetString = Ip.toString();
    const char *theLOCALTARGET = localTargetString.c_str();

    Serial.printf("theLOCALTARGET: %s\n", theLOCALTARGET);
    int res;

    int retries = 5;
    while (retries-- > 0) {
      res = getaddrinfo(theLOCALTARGET, "80", &s_hints, &s_target);
      if (res == 0)
        break;
      Serial.printf("getaddrinfo failed (%d). Retrying...\n", res);
      delay(1000);
    }
    if (res != 0) {
      Serial.printf("getaddrinfo failed after retries: %d\n", res);
    }
    // ssh_set_blocking(session, 1);

    time_t then = time(nullptr);
    ssh_ready = true;
    run_tunnel2(session);
    ssh_disconnect(session);
    ssh_free(session);
    ssh_finalize();
    time_t now = time(nullptr);
    time_t diff = now - then;
    if (diff < 60) {
      // rate limit connection attempts to 1 every60s
      DEBUG("Rate limit sleeps for %ds\n", 60 - diff);
      delay(1000 * (60 - diff));
    }
  }

  ssh_disconnect(session);
  ssh_free(session);
  ssh_finalize();
  ssh_ready = false;
  vTaskDelete(nullptr);
}
