// see us after school for copyright and license details

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <syslog.h>
#include <time.h>
#include <grp.h>
#include <pwd.h>
#include <err.h>
#include <glob.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <tls.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include "../config.h"

#define HEADER 2048

#ifndef __OpenBSD__
int pledge(const char *promises, const char *execpromises) {
  (void) promises;
  (void) execpromises;
  return 0;
}

int unveil(const char *path, const char *permissions) {
  (void) path;
  (void) permissions;
  return 0;
}
#endif

void prepare(char *path) {
  FILE *f = fopen("trust", "a");
  if(f) {
    fclose(f);
    return;
  } else {
    errx(1, "unable to create file %s", path);
  }
}

void attr(const char *subject, char *key, char *dst, int len) {
  char needle[len];
  snprintf(needle, len, "/%s=", key);
  char *found = strstr(subject, needle);
  if(found) {
    found += strlen(needle);
    char *end = strchr(found, '/');
    snprintf(dst, len, "%.*s", (int) (end - found), found);
  }
}

void tlswrite(struct tls *tls, char *buf, int len) {
  while(len > 0) {
    ssize_t ret = tls_write(tls, buf, len);
    if(ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) continue;
    if(ret == -1) errx(1, "tls_write: %s", tls_error(tls));
    buf += ret; len -= ret;
  }
}

int header(struct tls *ctx, int status, char *meta) {
  char buf[HEADER];
  int len = snprintf(buf, HEADER, "%d %s\r\n", status, *meta ? meta : "");
  tlswrite(ctx, buf, len);
  return 0;
}

int tofu(char *mailbox, char *host, char *fingerprint) {
  int len = strlen(mailbox) + strlen(host) + 2;
  int flen = strlen(fingerprint);
  char address[len];
  snprintf(address, len, "%s@%s", mailbox, host);

  FILE *f = fopen("trust", "r");
  if(!f)
    return 1;

  if(flock(fileno(f), LOCK_EX))
    return 1;

  char line[HEADER];
  while(fgets(line, sizeof(line), f)) {
    line[strcspn(line, "\n")] = 0;
    char *sp = strchr(line, ' ');
    if (!sp) {
      return 1;
    }
    *sp = '\0';
    char *mbox = line;
    char *fp = sp + 1;
    if(!strncmp(address, mbox, len)) {
      if(!strncmp(fingerprint, fp, flen)) {
        return 0;
      } else {
        return 1;
      }
    }
  }
  fclose(f);
  f = fopen("trust", "a");
  if(!f)
    return 1;
  if(flock(fileno(f), LOCK_EX))
    return 1;

  fprintf(f, "%s %s\n", address, fingerprint);
  fclose(f);

  return 0;
}

int waste(struct tls *ctx, char *ip, char *url) {
  time_t now = time(0);
  if(!tls_peer_cert_provided(ctx))
    return header(ctx, 60, "certificate required");

  char *hash = (char *) tls_peer_cert_hash(ctx);

  const char *subject = tls_peer_cert_subject(ctx);

  size_t attrlen = 128;
  char cn[attrlen], uid[attrlen];
  if(subject) {
    attr(subject, "CN", cn, attrlen);
    attr(subject, "UID", uid, attrlen);
  }

  int expired = 0;
  int first = tls_peer_cert_notbefore(ctx);
  int expiry = tls_peer_cert_notafter(ctx);
  if(first != -1 && difftime(now, first) < 0) expired = -1;
  if(expiry != -1 && difftime(expiry, now) > 0) expired = 1;
  if(expired)
    return header(ctx, 62, "expired certificate");

  size_t len;
  const uint8_t *pem = tls_peer_cert_chain_pem(ctx, &len);
  if(!pem)
    return header(ctx, 62, "invalid certificate");

  BIO *bio = BIO_new_mem_buf(pem, len);
  if(!bio)
    return header(ctx, 62, "invalid certificate");

  X509 *crt = PEM_read_bio_X509(bio, 0, 0, 0);
  if (!crt)
    return header(ctx, 62, "invalid certificate");

  STACK_OF(GENERAL_NAME) *names;;
  names = X509_get_ext_d2i(crt, NID_subject_alt_name, 0, 0);
  if(!names)
    return header(ctx, 62, "invalid certificate");

  char *host = 0;
  GENERAL_NAME *san = sk_GENERAL_NAME_value(names, 0);
  if(san->type == GEN_DNS) {
    host = (char *)ASN1_STRING_get0_data(san->d.dNSName);
  } else {
    return header(ctx, 62, "invalid certificate");
  }

  if(strlen(url) >= HEADER) return header(ctx, 59, "invalid request");
  if(strlen(url) <= 2) return header(ctx, 59, "invalid request");

  if(url[strlen(url) - 2] != '\r' || url[strlen(url) - 1] != '\n')
    return header(ctx, 59, "malformed request");

  url[strlen(url) - 2] = '\0';

  syslog(LOG_INFO, "%s %s {%s CN:%s}", url, ip, hash, uid);

  char *scheme = strsep(&url, ":");
  if(!url || strncmp(url, "//", 2)) return header(ctx, 59, "missing scheme");

  if(!strcmp(scheme, "misfin"))
    url += 2;
  else
    return header(ctx, 59, "unknown scheme");

  char *fingerprint = strchr(hash, ':') + 1;
  if(tofu(uid, host, fingerprint))
    return header(ctx, 63, "you're a liar");

  char *mailbox = strsep(&url, "@");
  char *hostname = strsep(&url, " ");
  char *message = url;
  if(message[strlen(message)] == '\r')
    message[strlen(message)] = '\0';

  struct passwd *pwd = getpwnam(mailbox);
  if(!pwd)
    return header(ctx, 51, "mailbox doesn't exist 1");
  
  if(pwd->pw_uid < minuid)
    return header(ctx, 51, "mailbox doesn't exist 2");

  char *home = pwd->pw_dir;
  if(!home)
    return header(ctx, 51, "mailbox doesn't exist 3");

  if(unveil(home, "rwc"))
    return header(ctx, 51, "mailbox doesn't exist");
  unveil(0, 0);

  char path[PATH_MAX] = { 0 };
  snprintf(path, PATH_MAX, "%s/.waste/waste.pem", home);

  FILE *f = fopen(path, "r");
  if(!f)
    return header(ctx, 51, "mailbox doesn't exist 4");

  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int mdlen = 0;

  crt = PEM_read_X509(f, 0, 0, 0);

  if (!X509_digest(crt, EVP_sha256(), md, &mdlen))
    return header(ctx, 51, "mailbox doesn't exist 5");

  char mbfingerprint[HEADER] = { 0 };
  char *p = mbfingerprint;
  for (unsigned int i = 0; i < mdlen; i++) {
    snprintf(p, 3, "%02x", md[i]);
    p += 2;
  }
  *p = '\0';

  pid_t pid = getpid();
  if (strlen(message) > 0) {
    char path[PATH_MAX] = { 0 };
    snprintf(path, PATH_MAX, "%s/.waste/inbox/%lld.%d.gmi", home, now, pid);

    umask(117);
    FILE *letter = fopen(path, "w");
    if(!letter)
      return header(ctx, 41, "server currently unvailable");

    char iso[HEADER];
    strftime(iso, sizeof(iso), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    fprintf(letter, "< %s@%s %s\n", uid, host, cn);
    fprintf(letter, ": %s@%s\n", mailbox, hostname);
    fprintf(letter, "@ %s\n\n", iso);
    fprintf(letter, "%s\n", message);
    fclose(letter);
  }

  return header(ctx, 20, mbfingerprint);
}

int main(int argc, char *argv[]) {
  int debug = 0;

  int c;
  while((c = getopt(argc, argv, "d")) != -1) {
    switch(c) {
      case 'd': debug = 1;
    }
  }

  tzset();

  struct sockaddr_in6 addr;
  int server = socket(AF_INET6, SOCK_STREAM, 0);

  struct tls_config *tlsconf = 0;
  struct tls *tls = 0;

  if(!(tls = tls_server())) errx(1, "tls_server failed");
  if(!(tlsconf = tls_config_new())) errx(1, "tls_config_new failed");

  if(tls_config_set_key_file(tlsconf, keyfile) < 0)
    errx(1, "tls_config_set_key_file failed");
  if(tls_config_set_cert_file(tlsconf, crtfile) < 0)
    errx(1, "tls_config_set_cert_file failed");

  tls_config_verify_client_optional(tlsconf);
  tls_config_insecure_noverifycert(tlsconf);

  if(tls_configure(tls, tlsconf) < 0)
    errx(1, "tls_configure failed");

  struct group *grp = { 0 };
  struct passwd *pwd = { 0 };

  if(group && !(grp = getgrnam(group)))
    errx(1, "group %s not found", group);

  if(user && !(pwd = getpwnam(user)))
    errx(1, "user %s not found", user);

  if(!debug)
    daemon(0, 0);

  if(unveil(root, "rwc")) errx(1, "unveil failed");
  if(chdir(root)) errx(1, "chdir failed");

  openlog("waste", LOG_NDELAY, LOG_DAEMON);

  prepare("trust");

  if(group && grp && setgid(grp->gr_gid)) errx(1, "setgid failed");
  if(user && pwd && setuid(pwd->pw_uid)) errx(1, "setuid failed");

  if(pledge("stdio inet proc dns rpath wpath cpath getpw unix flock unveil", 0))
    errx(1, "pledge failed");

  bzero(&addr, sizeof(addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(1958);
  addr.sin6_addr = in6addr_loopback;

  struct timeval timeout;
  timeout.tv_sec = 10;

  int opt = 1;
  setsockopt(server, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
  setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(server, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  if(bind(server, (struct sockaddr *) &addr, (socklen_t) sizeof(addr)))
    errx(1, "bind failed %d", errno);

  listen(server, 32);

  int sock;
  socklen_t len = sizeof(addr);
  while((sock = accept(server, (struct sockaddr *) &addr, &len)) > -1) {
    pid_t pid = fork();
    if(pid == -1) errx(1, "fork failed");

    struct tls *ctx = 0;
    if(!pid) {
      close(server);
      if(tls_accept_socket(tls, &ctx, sock) < 0)
        errx(1, "tls_accept_socket failed");
      char url[HEADER] = { 0 };
      if(tls_read(ctx, url, HEADER) == -1) {
        tls_close(ctx);
        errx(1, "tls_read failed");
      }
      char ip[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &addr, ip, INET6_ADDRSTRLEN);
      waste(ctx, ip, url);
      tls_close(ctx);
    } else {
      close(sock);
      signal(SIGCHLD, SIG_IGN);
    }
  }
  tls_close(tls);
  tls_free(tls);
  tls_config_free(tlsconf);
  closelog();
  return 0;
}
