/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

*/

/*
 * Loopback OSXFUSE file system in C. Uses the high-level FUSE API.
 * Based on the fusexmp_fh.c example from the Linux FUSE distribution.
 * Amit Singh <http://osxbook.com>
 */

#include <AvailabilityMacros.h>

#if MAC_OS_X_VERSION_MIN_REQUIRED < 1050
#error "This file system requires Leopard and above."
#endif

#define FUSE_USE_VERSION 26

#define _GNU_SOURCE

#include <fuse.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <sys/attr.h>
#include <sys/param.h>
#include <sys/vnode.h>

#if defined(_POSIX_C_SOURCE)
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;
#endif

#define G_PREFIX "org"
#define G_KAUTH_FILESEC_XATTR G_PREFIX ".apple.system.Security"
#define A_PREFIX "com"
#define A_KAUTH_FILESEC_XATTR A_PREFIX ".apple.system.Security"
#define XATTR_APPLE_PREFIX "com.apple."

struct dropboxpp {
  int case_insensitive;
};

static struct dropboxpp dropboxpp;

static int dropboxpp_getattr(const char *path, struct stat *stbuf) {
  int res;

  res = lstat(path, stbuf);

#if FUSE_VERSION >= 29
  /*
   * The optimal I/O size can be set on a per-file basis. Setting st_blksize
   * to zero will cause the kernel extension to fall back on the global I/O
   * size which can be specified at mount-time (option iosize).
   */
  stbuf->st_blksize = 0;
#endif

  if (res == -1) {
    return -errno;
  }

  return 0;
}

static int dropboxpp_fgetattr(const char *path, struct stat *stbuf,
                             struct fuse_file_info *fi) {
  int res;

  (void)path;

  res = fstat(fi->fh, stbuf);

#if FUSE_VERSION >= 29
  // Fall back to global I/O size. See dropboxpp_getattr().
  stbuf->st_blksize = 0;
#endif

  if (res == -1) {
    return -errno;
  }

  return 0;
}

static int dropboxpp_readlink(const char *path, char *buf, size_t size) {
  int res;

  res = readlink(path, buf, size - 1);
  if (res == -1) {
    return -errno;
  }

  buf[res] = '\0';

  return 0;
}

struct dropboxpp_dirp {
  DIR *dp;
  struct dirent *entry;
  off_t offset;
};

static int dropboxpp_opendir(const char *path, struct fuse_file_info *fi) {
  int res;

  struct dropboxpp_dirp *d = malloc(sizeof(struct dropboxpp_dirp));
  if (d == NULL) {
    return -ENOMEM;
  }

  d->dp = opendir(path);
  if (d->dp == NULL) {
    res = -errno;
    free(d);
    return res;
  }

  d->offset = 0;
  d->entry = NULL;

  fi->fh = (unsigned long)d;

  return 0;
}

static inline struct dropboxpp_dirp *get_dirp(struct fuse_file_info *fi) {
  return (struct dropboxpp_dirp *)(uintptr_t)fi->fh;
}

struct delayed_dir {
  char entry_name[255 + 1];
  struct stat st;
  off_t nextoff;
};

static int dropboxpp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                            off_t offset, struct fuse_file_info *fi) {
  struct dropboxpp_dirp *d = get_dirp(fi);

  if (offset != d->offset) {
    seekdir(d->dp, offset);
    d->entry = NULL;
    d->offset = offset;
  }

  struct delayed_dir default_dirs[2];
  struct delayed_dir delayed_arr[1024];
  int delayed_i = 0;

  int isgitdir = 0;
  while (1) {
    if (!d->entry) {
      d->entry = readdir(d->dp);
      if (!d->entry) {
        break;
      }
    }

    if (d->entry->d_type == DT_DIR && strcmp(d->entry->d_name, ".git") == 0) {
      isgitdir = 1;
      break;
    }

    struct delayed_dir *delayed;
    if (strcmp(d->entry->d_name, ".") == 0) {
      delayed = &default_dirs[0];
    } else if (strcmp(d->entry->d_name, "..") == 0) {
      delayed = &default_dirs[1];
    } else {
      delayed = &delayed_arr[delayed_i++];
    }

    strcpy(delayed->entry_name, d->entry->d_name);

    struct stat *st = &delayed->st;
    memset(st, 0, sizeof(struct stat));
    st->st_ino = d->entry->d_ino;
    st->st_mode = d->entry->d_type << 12;

    delayed->nextoff = telldir(d->dp);

    d->entry = NULL;
    d->offset = delayed->nextoff;
  }

  struct delayed_dir *delayed;
  for (int i = 0; i < 2; i++) {
    delayed = &default_dirs[i];
    if (filler(buf, delayed->entry_name, &delayed->st, delayed->nextoff)) {
      return 0;
    }
  }
  if (!isgitdir) {
    for (int i = 0; i < delayed_i; i++) {
      delayed = &delayed_arr[i];
      if (filler(buf, delayed->entry_name, &delayed->st, delayed->nextoff)) {
        return 0;
      }
    }
  }

  return 0;
}

static int dropboxpp_releasedir(const char *path, struct fuse_file_info *fi) {
  struct dropboxpp_dirp *d = get_dirp(fi);

  (void)path;

  closedir(d->dp);
  free(d);

  return 0;
}

static int dropboxpp_mknod(const char *path, mode_t mode, dev_t rdev) {
  int res;

  if (S_ISFIFO(mode)) {
    res = mkfifo(path, mode);
  } else {
    res = mknod(path, mode, rdev);
  }

  if (res == -1) {
    return -errno;
  }

  return 0;
}

static int dropboxpp_mkdir(const char *path, mode_t mode) {
  int res;

  res = mkdir(path, mode);
  if (res == -1) {
    return -errno;
  }

  return 0;
}

static int dropboxpp_unlink(const char *path) {
  int res;

  res = unlink(path);
  if (res == -1) {
    return -errno;
  }

  return 0;
}

static int dropboxpp_rmdir(const char *path) {
  int res;

  res = rmdir(path);
  if (res == -1) {
    return -errno;
  }

  return 0;
}

static int dropboxpp_symlink(const char *from, const char *to) {
  int res;

  res = symlink(from, to);
  if (res == -1) {
    return -errno;
  }

  return 0;
}

static int dropboxpp_rename(const char *from, const char *to) {
  int res;

  res = rename(from, to);
  if (res == -1) {
    return -errno;
  }

  return 0;
}

static int dropboxpp_exchange(const char *path1, const char *path2,
                             unsigned long options) {
  int res;

  res = exchangedata(path1, path2, options);
  if (res == -1) {
    return -errno;
  }

  return 0;
}

static int dropboxpp_link(const char *from, const char *to) {
  int res;

  res = link(from, to);
  if (res == -1) {
    return -errno;
  }

  return 0;
}

#if MAC_OS_X_VERSION_MIN_REQUIRED >= 1060

static int dropboxpp_fsetattr_x(const char *path, struct setattr_x *attr,
                               struct fuse_file_info *fi) {
  int res;
  uid_t uid = -1;
  gid_t gid = -1;

  if (SETATTR_WANTS_MODE(attr)) {
    res = fchmod(fi->fh, attr->mode);
    if (res == -1) {
      return -errno;
    }
  }

  if (SETATTR_WANTS_UID(attr)) {
    uid = attr->uid;
  }

  if (SETATTR_WANTS_GID(attr)) {
    gid = attr->gid;
  }

  if ((uid != -1) || (gid != -1)) {
    res = fchown(fi->fh, uid, gid);
    if (res == -1) {
      return -errno;
    }
  }

  if (SETATTR_WANTS_SIZE(attr)) {
    res = ftruncate(fi->fh, attr->size);
    if (res == -1) {
      return -errno;
    }
  }

  if (SETATTR_WANTS_MODTIME(attr)) {
    struct timeval tv[2];
    if (!SETATTR_WANTS_ACCTIME(attr)) {
      gettimeofday(&tv[0], NULL);
    } else {
      tv[0].tv_sec = attr->acctime.tv_sec;
      tv[0].tv_usec = attr->acctime.tv_nsec / 1000;
    }
    tv[1].tv_sec = attr->modtime.tv_sec;
    tv[1].tv_usec = attr->modtime.tv_nsec / 1000;
    res = futimes(fi->fh, tv);
    if (res == -1) {
      return -errno;
    }
  }

  if (SETATTR_WANTS_CRTIME(attr)) {
    struct attrlist attributes;

    attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
    attributes.reserved = 0;
    attributes.commonattr = ATTR_CMN_CRTIME;
    attributes.dirattr = 0;
    attributes.fileattr = 0;
    attributes.forkattr = 0;
    attributes.volattr = 0;

    res = fsetattrlist(fi->fh, &attributes, &attr->crtime,
                       sizeof(struct timespec), FSOPT_NOFOLLOW);

    if (res == -1) {
      return -errno;
    }
  }

  if (SETATTR_WANTS_CHGTIME(attr)) {
    struct attrlist attributes;

    attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
    attributes.reserved = 0;
    attributes.commonattr = ATTR_CMN_CHGTIME;
    attributes.dirattr = 0;
    attributes.fileattr = 0;
    attributes.forkattr = 0;
    attributes.volattr = 0;

    res = fsetattrlist(fi->fh, &attributes, &attr->chgtime,
                       sizeof(struct timespec), FSOPT_NOFOLLOW);

    if (res == -1) {
      return -errno;
    }
  }

  if (SETATTR_WANTS_BKUPTIME(attr)) {
    struct attrlist attributes;

    attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
    attributes.reserved = 0;
    attributes.commonattr = ATTR_CMN_BKUPTIME;
    attributes.dirattr = 0;
    attributes.fileattr = 0;
    attributes.forkattr = 0;
    attributes.volattr = 0;

    res = fsetattrlist(fi->fh, &attributes, &attr->bkuptime,
                       sizeof(struct timespec), FSOPT_NOFOLLOW);

    if (res == -1) {
      return -errno;
    }
  }

  if (SETATTR_WANTS_FLAGS(attr)) {
    res = fchflags(fi->fh, attr->flags);
    if (res == -1) {
      return -errno;
    }
  }

  return 0;
}

#endif /* MAC_OS_X_VERSION_MIN_REQUIRED >= 1060 */

static int dropboxpp_setattr_x(const char *path, struct setattr_x *attr) {
  int res;
  uid_t uid = -1;
  gid_t gid = -1;

  if (SETATTR_WANTS_MODE(attr)) {
    res = lchmod(path, attr->mode);
    if (res == -1) {
      return -errno;
    }
  }

  if (SETATTR_WANTS_UID(attr)) {
    uid = attr->uid;
  }

  if (SETATTR_WANTS_GID(attr)) {
    gid = attr->gid;
  }

  if ((uid != -1) || (gid != -1)) {
    res = lchown(path, uid, gid);
    if (res == -1) {
      return -errno;
    }
  }

  if (SETATTR_WANTS_SIZE(attr)) {
    res = truncate(path, attr->size);
    if (res == -1) {
      return -errno;
    }
  }

  if (SETATTR_WANTS_MODTIME(attr)) {
    struct timeval tv[2];
    if (!SETATTR_WANTS_ACCTIME(attr)) {
      gettimeofday(&tv[0], NULL);
    } else {
      tv[0].tv_sec = attr->acctime.tv_sec;
      tv[0].tv_usec = attr->acctime.tv_nsec / 1000;
    }
    tv[1].tv_sec = attr->modtime.tv_sec;
    tv[1].tv_usec = attr->modtime.tv_nsec / 1000;
    res = lutimes(path, tv);
    if (res == -1) {
      return -errno;
    }
  }

  if (SETATTR_WANTS_CRTIME(attr)) {
    struct attrlist attributes;

    attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
    attributes.reserved = 0;
    attributes.commonattr = ATTR_CMN_CRTIME;
    attributes.dirattr = 0;
    attributes.fileattr = 0;
    attributes.forkattr = 0;
    attributes.volattr = 0;

    res = setattrlist(path, &attributes, &attr->crtime, sizeof(struct timespec),
                      FSOPT_NOFOLLOW);

    if (res == -1) {
      return -errno;
    }
  }

  if (SETATTR_WANTS_CHGTIME(attr)) {
    struct attrlist attributes;

    attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
    attributes.reserved = 0;
    attributes.commonattr = ATTR_CMN_CHGTIME;
    attributes.dirattr = 0;
    attributes.fileattr = 0;
    attributes.forkattr = 0;
    attributes.volattr = 0;

    res = setattrlist(path, &attributes, &attr->chgtime,
                      sizeof(struct timespec), FSOPT_NOFOLLOW);

    if (res == -1) {
      return -errno;
    }
  }

  if (SETATTR_WANTS_BKUPTIME(attr)) {
    struct attrlist attributes;

    attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
    attributes.reserved = 0;
    attributes.commonattr = ATTR_CMN_BKUPTIME;
    attributes.dirattr = 0;
    attributes.fileattr = 0;
    attributes.forkattr = 0;
    attributes.volattr = 0;

    res = setattrlist(path, &attributes, &attr->bkuptime,
                      sizeof(struct timespec), FSOPT_NOFOLLOW);

    if (res == -1) {
      return -errno;
    }
  }

  if (SETATTR_WANTS_FLAGS(attr)) {
    res = lchflags(path, attr->flags);
    if (res == -1) {
      return -errno;
    }
  }

  return 0;
}

static int dropboxpp_getxtimes(const char *path, struct timespec *bkuptime,
                              struct timespec *crtime) {
  int res = 0;
  struct attrlist attributes;

  attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
  attributes.reserved = 0;
  attributes.commonattr = 0;
  attributes.dirattr = 0;
  attributes.fileattr = 0;
  attributes.forkattr = 0;
  attributes.volattr = 0;

  struct xtimeattrbuf {
    uint32_t size;
    struct timespec xtime;
  } __attribute__((packed));

  struct xtimeattrbuf buf;

  attributes.commonattr = ATTR_CMN_BKUPTIME;
  res = getattrlist(path, &attributes, &buf, sizeof(buf), FSOPT_NOFOLLOW);
  if (res == 0) {
    (void)memcpy(bkuptime, &(buf.xtime), sizeof(struct timespec));
  } else {
    (void)memset(bkuptime, 0, sizeof(struct timespec));
  }

  attributes.commonattr = ATTR_CMN_CRTIME;
  res = getattrlist(path, &attributes, &buf, sizeof(buf), FSOPT_NOFOLLOW);
  if (res == 0) {
    (void)memcpy(crtime, &(buf.xtime), sizeof(struct timespec));
  } else {
    (void)memset(crtime, 0, sizeof(struct timespec));
  }

  return 0;
}

static int dropboxpp_create(const char *path, mode_t mode,
                           struct fuse_file_info *fi) {
  int fd;

  fd = open(path, fi->flags, mode);
  if (fd == -1) {
    return -errno;
  }

  fi->fh = fd;
  return 0;
}

static int dropboxpp_open(const char *path, struct fuse_file_info *fi) {
  int fd;

  fd = open(path, fi->flags);
  if (fd == -1) {
    return -errno;
  }

  fi->fh = fd;
  return 0;
}

static int dropboxpp_read(const char *path, char *buf, size_t size, off_t offset,
                         struct fuse_file_info *fi) {
  int res;

  (void)path;
  res = pread(fi->fh, buf, size, offset);
  if (res == -1) {
    res = -errno;
  }

  return res;
}

static int dropboxpp_write(const char *path, const char *buf, size_t size,
                          off_t offset, struct fuse_file_info *fi) {
  int res;

  (void)path;

  res = pwrite(fi->fh, buf, size, offset);
  if (res == -1) {
    res = -errno;
  }

  return res;
}

static int dropboxpp_statfs(const char *path, struct statvfs *stbuf) {
  int res;

  res = statvfs(path, stbuf);
  if (res == -1) {
    return -errno;
  }

  return 0;
}

static int dropboxpp_flush(const char *path, struct fuse_file_info *fi) {
  int res;

  (void)path;

  res = close(dup(fi->fh));
  if (res == -1) {
    return -errno;
  }

  return 0;
}

static int dropboxpp_release(const char *path, struct fuse_file_info *fi) {
  (void)path;

  close(fi->fh);

  return 0;
}

static int dropboxpp_fsync(const char *path, int isdatasync,
                          struct fuse_file_info *fi) {
  int res;

  (void)path;

  (void)isdatasync;

  res = fsync(fi->fh);
  if (res == -1) {
    return -errno;
  }

  return 0;
}

static int dropboxpp_setxattr(const char *path, const char *name,
                             const char *value, size_t size, int flags,
                             uint32_t position) {
  int res;

  if (!strncmp(name, XATTR_APPLE_PREFIX, sizeof(XATTR_APPLE_PREFIX) - 1)) {
    flags &= ~(XATTR_NOSECURITY);
  }

  if (!strcmp(name, A_KAUTH_FILESEC_XATTR)) {

    char new_name[MAXPATHLEN];

    memcpy(new_name, A_KAUTH_FILESEC_XATTR, sizeof(A_KAUTH_FILESEC_XATTR));
    memcpy(new_name, G_PREFIX, sizeof(G_PREFIX) - 1);

    res = setxattr(path, new_name, value, size, position, XATTR_NOFOLLOW);

  } else {
    res = setxattr(path, name, value, size, position, XATTR_NOFOLLOW);
  }

  if (res == -1) {
    return -errno;
  }

  return 0;
}

static int dropboxpp_getxattr(const char *path, const char *name, char *value,
                             size_t size, uint32_t position) {
  int res;

  if (strcmp(name, A_KAUTH_FILESEC_XATTR) == 0) {

    char new_name[MAXPATHLEN];

    memcpy(new_name, A_KAUTH_FILESEC_XATTR, sizeof(A_KAUTH_FILESEC_XATTR));
    memcpy(new_name, G_PREFIX, sizeof(G_PREFIX) - 1);

    res = getxattr(path, new_name, value, size, position, XATTR_NOFOLLOW);

  } else {
    res = getxattr(path, name, value, size, position, XATTR_NOFOLLOW);
  }

  if (res == -1) {
    return -errno;
  }

  return res;
}

static int dropboxpp_listxattr(const char *path, char *list, size_t size) {
  ssize_t res = listxattr(path, list, size, XATTR_NOFOLLOW);
  if (res > 0) {
    if (list) {
      size_t len = 0;
      char *curr = list;
      do {
        size_t thislen = strlen(curr) + 1;
        if (strcmp(curr, G_KAUTH_FILESEC_XATTR) == 0) {
          memmove(curr, curr + thislen, res - len - thislen);
          res -= thislen;
          break;
        }
        curr += thislen;
        len += thislen;
      } while (len < res);
    } else {
      /*
      ssize_t res2 = getxattr(path, G_KAUTH_FILESEC_XATTR, NULL, 0, 0,
                              XATTR_NOFOLLOW);
      if (res2 >= 0) {
          res -= sizeof(G_KAUTH_FILESEC_XATTR);
      }
      */
    }
  }

  if (res == -1) {
    return -errno;
  }

  return res;
}

static int dropboxpp_removexattr(const char *path, const char *name) {
  int res;

  if (strcmp(name, A_KAUTH_FILESEC_XATTR) == 0) {

    char new_name[MAXPATHLEN];

    memcpy(new_name, A_KAUTH_FILESEC_XATTR, sizeof(A_KAUTH_FILESEC_XATTR));
    memcpy(new_name, G_PREFIX, sizeof(G_PREFIX) - 1);

    res = removexattr(path, new_name, XATTR_NOFOLLOW);

  } else {
    res = removexattr(path, name, XATTR_NOFOLLOW);
  }

  if (res == -1) {
    return -errno;
  }

  return 0;
}

#if FUSE_VERSION >= 29

static int dropboxpp_fallocate(const char *path, int mode, off_t offset,
                              off_t length, struct fuse_file_info *fi) {
  fstore_t fstore;

  if (!(mode & PREALLOCATE)) {
    return -ENOTSUP;
  }

  fstore.fst_flags = 0;
  if (mode & ALLOCATECONTIG) {
    fstore.fst_flags |= F_ALLOCATECONTIG;
  }
  if (mode & ALLOCATEALL) {
    fstore.fst_flags |= F_ALLOCATEALL;
  }

  if (mode & ALLOCATEFROMPEOF) {
    fstore.fst_posmode = F_PEOFPOSMODE;
  } else if (mode & ALLOCATEFROMVOL) {
    fstore.fst_posmode = F_VOLPOSMODE;
  }

  fstore.fst_offset = offset;
  fstore.fst_length = length;

  if (fcntl(fi->fh, F_PREALLOCATE, &fstore) == -1) {
    return -errno;
  } else {
    return 0;
  }
}

#endif /* FUSE_VERSION >= 29 */

static int dropboxpp_setvolname(const char *name) { return 0; }

void *dropboxpp_init(struct fuse_conn_info *conn) {
  FUSE_ENABLE_SETVOLNAME(conn);
  FUSE_ENABLE_XTIMES(conn);

#ifdef FUSE_ENABLE_CASE_INSENSITIVE
  if (dropboxpp.case_insensitive) {
    FUSE_ENABLE_CASE_INSENSITIVE(conn);
  }
#endif

  return NULL;
}

void dropboxpp_destroy(void *userdata) { /* nothing */
}

static struct fuse_operations dropboxpp_oper = {
    .init = dropboxpp_init,
    .destroy = dropboxpp_destroy,
    .getattr = dropboxpp_getattr,
    .fgetattr = dropboxpp_fgetattr,
    /*  .access      = dropboxpp_access, */
    .readlink = dropboxpp_readlink,
    .opendir = dropboxpp_opendir,
    .readdir = dropboxpp_readdir,
    .releasedir = dropboxpp_releasedir,
    .mknod = dropboxpp_mknod,
    .mkdir = dropboxpp_mkdir,
    .symlink = dropboxpp_symlink,
    .unlink = dropboxpp_unlink,
    .rmdir = dropboxpp_rmdir,
    .rename = dropboxpp_rename,
    .link = dropboxpp_link,
    .create = dropboxpp_create,
    .open = dropboxpp_open,
    .read = dropboxpp_read,
    .write = dropboxpp_write,
    .statfs = dropboxpp_statfs,
    .flush = dropboxpp_flush,
    .release = dropboxpp_release,
    .fsync = dropboxpp_fsync,
    .setxattr = dropboxpp_setxattr,
    .getxattr = dropboxpp_getxattr,
    .listxattr = dropboxpp_listxattr,
    .removexattr = dropboxpp_removexattr,
    .exchange = dropboxpp_exchange,
    .getxtimes = dropboxpp_getxtimes,
    .setattr_x = dropboxpp_setattr_x,
#if MAC_OS_X_VERSION_MIN_REQUIRED >= 1060
    .fsetattr_x = dropboxpp_fsetattr_x,
#endif
#if FUSE_VERSION >= 29
    .fallocate = dropboxpp_fallocate,
#endif
    .setvolname = dropboxpp_setvolname,

#if FUSE_VERSION >= 29
    .flag_nullpath_ok = 1,
    .flag_nopath = 1,
#endif
};

static const struct fuse_opt dropboxpp_opts[] = {
    {"case_insensitive", offsetof(struct dropboxpp, case_insensitive), 1},
    FUSE_OPT_END};

int main(int argc, char *argv[]) {
  int res = 0;
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

  dropboxpp.case_insensitive = 0;
  if (fuse_opt_parse(&args, &dropboxpp, dropboxpp_opts, NULL) == -1) {
    exit(1);
  }

  umask(0);
  res = fuse_main(args.argc, args.argv, &dropboxpp_oper, NULL);

  fuse_opt_free_args(&args);
  return res;
}
