//
//  iOSFS.m
//  iSH
//
//  Created by Noah Peeters on 26.10.19.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include <sys/stat.h>
#include "SceneDelegate.h"
#include "iOSFS.h"
#include "kernel/fs.h"
#include "kernel/errno.h"
#include "fs/path.h"

const NSFileCoordinatorWritingOptions NSFileCoordinatorWritingForCreating = NSFileCoordinatorWritingForMerging;

@interface DirectoryPickerDelegate : NSObject <UIDocumentPickerDelegate>

@property NSURL *url;
@property pthread_mutex_t *mutex;

@end

@implementation DirectoryPickerDelegate

- (instancetype)initWithMutex:(pthread_mutex_t *)mutex {
    if (self = [super init]) {
        self.mutex = mutex;
        self.url = nil;
        pthread_mutex_lock(mutex);
    }
    return self;
}

- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller {
    pthread_mutex_unlock(self.mutex);
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    if (urls.count > 0)
        self.url = urls[0];
    pthread_mutex_unlock(self.mutex);
}

@end

NSURL *url_for_mount(struct mount *mount) {
    return (__bridge NSURL *) mount->data;
}

NSURL *url_for_path_in_mount(struct mount *mount, const char *path) {
    return [[url_for_mount(mount) URLByAppendingPathComponent:[NSString stringWithUTF8String:path]] URLByStandardizingPath];
}

const char *path_for_url_in_mount(struct mount *mount, NSURL *url, const char *fallback) {
    NSString *mount_path = [[url_for_mount(mount) URLByStandardizingPath] path];
    NSString *url_path = [[url URLByStandardizingPath] path];

    // The `/private` prefix is a special case as described in the documentation of `URLByStandardizingPath`.
    if ([mount_path hasPrefix:@"/private/"]) mount_path = [mount_path substringFromIndex:8];
    if ([url_path   hasPrefix:@"/private/"]) url_path   = [url_path   substringFromIndex:8];

    if (![url_path hasPrefix:mount_path])
        return fallback;

    NSURL *new_url = [NSURL fileURLWithPath:[url_path substringFromIndex:[mount_path length]]];
    return [new_url ? [new_url path] : @"" cStringUsingEncoding:NSUTF8StringEncoding];
}

static int iosfs_stat(struct mount *mount, const char *path, struct statbuf *fake_stat, bool follow_links);
const struct fd_ops iosfs_fdops;

static int posixErrorFromNSError(NSError *error) {
    if (error != nil) {
        NSError *underlyingError = [error.userInfo objectForKey:NSUnderlyingErrorKey];
        if (underlyingError) {
            return -(int)underlyingError.code
            ;
        } else {
            return _EPERM;
        }
    }

    return 0;
}

static int combine_error(NSError *coordinatorError, int err) {
    int posix_error = posixErrorFromNSError(coordinatorError);
    return posix_error ? posix_error : err;
}

static struct fd *iosfs_open(struct mount *mount, const char *path, int flags, int mode) {
    NSURL *url = url_for_path_in_mount(mount, path);

    struct statbuf stats;
    int err = iosfs_stat(mount, path, &stats, false);

    if (!err && S_ISREG(stats.mode)) {
        NSFileCoordinator *coordinator = [[NSFileCoordinator alloc] initWithFilePresenter:nil];

        __block pthread_mutex_t open_mutex = PTHREAD_MUTEX_INITIALIZER;
        pthread_mutex_lock(&open_mutex);

        __block NSError *error;
        __block struct fd *openedFile;

        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^(void){
            void (^operation)(NSURL *url) = ^(NSURL *url) {
                openedFile = realfs_open_with_fdops(mount, path_for_url_in_mount(mount, url, path), flags, mode, &iosfs_fdops);

                if (IS_ERR(openedFile)) {
                    pthread_mutex_unlock(&open_mutex);
                } else {
                    pthread_mutex_t close_mutex = PTHREAD_MUTEX_INITIALIZER;
                    pthread_mutex_lock(&close_mutex);
                    openedFile->data = &close_mutex;
                    pthread_mutex_unlock(&open_mutex);

                    pthread_mutex_lock(&close_mutex);
                    pthread_mutex_unlock(&close_mutex);
                }
            };

            if (!(flags & O_WRONLY_) && !(flags & O_RDWR_)) {
                [coordinator coordinateReadingItemAtURL:url options:NSFileCoordinatorReadingWithoutChanges error:&error byAccessor:operation];
            } else if (flags & O_CREAT_) {
                [coordinator coordinateWritingItemAtURL:url options:NSFileCoordinatorWritingForCreating error:&error byAccessor:operation];
            } else {
                [coordinator coordinateWritingItemAtURL:url options:NSFileCoordinatorWritingForMerging error:&error byAccessor:operation];
            }
        });

        pthread_mutex_lock(&open_mutex);
        pthread_mutex_unlock(&open_mutex);

        int posix_error = posixErrorFromNSError(error);
        return posix_error ? ERR_PTR(posix_error) : openedFile;
    } else {
        return realfs_open_with_fdops(mount, path, flags, mode, &iosfs_fdops);
    }
}

int iosfs_close(struct fd *fd) {
    int err = realfs.close(fd);

    if (fd->data) {
        pthread_mutex_t *mutex = (pthread_mutex_t *)fd->data;
        pthread_mutex_unlock(mutex);
    }
    return err;
}

static int iosfs_ask_for_url(NSURL **url) {
    TerminalViewController *terminalViewController = currentTerminalViewController;

    if (!terminalViewController)
        return _ENODEV;

    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    DirectoryPickerDelegate *pickerDelegate = [[DirectoryPickerDelegate alloc] initWithMutex:&mutex];

    dispatch_async(dispatch_get_main_queue(), ^(void) {
        UIDocumentPickerViewController *picker = [[UIDocumentPickerViewController alloc] initWithDocumentTypes:@[ @"public.folder" ] inMode:UIDocumentPickerModeOpen];
        picker.delegate = pickerDelegate;
        [terminalViewController presentViewController:picker animated:true completion:nil];
    });

    pthread_mutex_lock(&mutex);
    pthread_mutex_unlock(&mutex);

    if (pickerDelegate.url == nil)
        return _ENODEV;

    *url = pickerDelegate.url;
    return 0;
}

static int iosfs_mount(struct mount *mount) {
    NSURL *url;

    int err = iosfs_ask_for_url(&url);
    if (err)
        return err;

    // Overwrite url & base path
    mount->data = (void *)CFBridgingRetain(url);
    mount->source = strdup([[url path] UTF8String]);

    if ([url startAccessingSecurityScopedResource] == NO) {
        CFBridgingRelease(mount->data);
        return _EPERM;
    }

    return realfs.mount(mount);
}

static int iosfs_umount(struct mount *mount) {
    NSURL *url = url_for_mount(mount);
    [url stopAccessingSecurityScopedResource];
    CFBridgingRelease(mount->data);

    return 0;
}

static int iosfs_rename(struct mount *mount, const char *src, const char *dst) {
    NSFileCoordinator *coordinator = [[NSFileCoordinator alloc] initWithFilePresenter:nil];
    NSURL *src_url = url_for_path_in_mount(mount, src);
    NSURL *dst_url = url_for_path_in_mount(mount, dst);

    NSError *error;
    __block int err;

    [coordinator coordinateWritingItemAtURL:src_url options:NSFileCoordinatorWritingForMoving error:&error byAccessor:^(NSURL *url) {
        [coordinator itemAtURL:url willMoveToURL:dst_url];
        err = realfs.rename(mount, path_for_url_in_mount(mount, url, src), dst);
        [coordinator itemAtURL:url didMoveToURL:dst_url];
    }];

    return combine_error(error, err);
}

static int iosfs_symlink(struct mount *mount, const char *target, const char *link) {
    NSFileCoordinator *coordinator = [[NSFileCoordinator alloc] initWithFilePresenter:nil];
    NSURL *dst_url = url_for_path_in_mount(mount, link);

    NSError *error;
    __block int err;

    [coordinator coordinateWritingItemAtURL:dst_url options:NSFileCoordinatorWritingForCreating error:&error byAccessor:^(NSURL *url) {
        err = realfs.symlink(mount, path_for_url_in_mount(mount, url, target), link);
    }];

    return combine_error(error, err);
}

static int iosfs_mknod(struct mount *mount, const char *path, mode_t_ mode, dev_t_ dev) {
    NSFileCoordinator *coordinator = [[NSFileCoordinator alloc] initWithFilePresenter:nil];
    NSURL *in_url = url_for_path_in_mount(mount, path);

    NSError *error;
    __block int err;

    [coordinator coordinateWritingItemAtURL:in_url options:NSFileCoordinatorWritingForCreating error:&error byAccessor:^(NSURL *url) {
        err = realfs.mknod(mount, path_for_url_in_mount(mount, url, path), mode, dev);
    }];

    return combine_error(error, err);
}

static int iosfs_setattr(struct mount *mount, const char *path, struct attr attr) {
    NSFileCoordinator *coordinator = [[NSFileCoordinator alloc] initWithFilePresenter:nil];
    NSURL *in_url = url_for_path_in_mount(mount, path);

    NSError *error;
    __block int err;

    [coordinator coordinateWritingItemAtURL:in_url options:NSFileCoordinatorWritingContentIndependentMetadataOnly error:&error byAccessor:^(NSURL *url) {
        err = realfs.setattr(mount, path_for_url_in_mount(mount, url, path), attr);
    }];

    return combine_error(error, err);
}

static int iosfs_fsetattr(struct fd *fd, struct attr attr) {
    return realfs.fsetattr(fd, attr);
}

static ssize_t iosfs_readlink(struct mount *mount, const char *path, char *buf, size_t bufsize) {
    NSFileCoordinator *coordinator = [[NSFileCoordinator alloc] initWithFilePresenter:nil];
    NSURL *in_url = url_for_path_in_mount(mount, path);

    NSError *error;
    __block ssize_t size;

    [coordinator coordinateReadingItemAtURL:in_url options:NSFileCoordinatorReadingWithoutChanges error:&error byAccessor:^(NSURL *url) {
        size = realfs.readlink(mount, path_for_url_in_mount(mount, url, path), buf, bufsize);
    }];

    int posix_error = posixErrorFromNSError(error);
    return posix_error ? posix_error : size;
}

static int iosfs_getpath(struct fd *fd, char *buf) {
    return realfs.getpath(fd, buf);
}

static int iosfs_link(struct mount *mount, const char *src, const char *dst) {
    NSFileCoordinator *coordinator = [[NSFileCoordinator alloc] initWithFilePresenter:nil];
    NSURL *dst_url = url_for_path_in_mount(mount, dst);

    NSError *error;
    __block int err;

    [coordinator coordinateWritingItemAtURL:dst_url options:NSFileCoordinatorWritingForCreating error:&error byAccessor:^(NSURL *url) {
        err = realfs.link(mount, src, path_for_url_in_mount(mount, url, dst));
    }];

    return combine_error(error, err);
}

static int iosfs_unlink(struct mount *mount, const char *path) {
    NSFileCoordinator *coordinator = [[NSFileCoordinator alloc] initWithFilePresenter:nil];
    NSURL *in_url = url_for_path_in_mount(mount, path);

    NSError *error;
    __block int err;

    [coordinator coordinateWritingItemAtURL:in_url options:NSFileCoordinatorWritingForDeleting error:&error byAccessor:^(NSURL *url) {
        err = realfs.unlink(mount, path_for_url_in_mount(mount, url, path));
    }];

    return combine_error(error, err);
}

static int iosfs_rmdir(struct mount *mount, const char *path) {
    NSFileCoordinator *coordinator = [[NSFileCoordinator alloc] initWithFilePresenter:nil];
    NSURL *in_url = url_for_path_in_mount(mount, path);

    NSError *error;
    __block int err;

    [coordinator coordinateWritingItemAtURL:in_url options:NSFileCoordinatorWritingForDeleting error:&error byAccessor:^(NSURL *url) {
        err = realfs.rmdir(mount, path_for_url_in_mount(mount, url, path));
    }];

    return combine_error(error, err);
}

static int iosfs_stat(struct mount *mount, const char *path, struct statbuf *fake_stat, bool follow_links) {
    NSFileCoordinator *coordinator = [[NSFileCoordinator alloc] initWithFilePresenter:nil];
    NSURL *in_url = url_for_path_in_mount(mount, path);

    NSError *error;
    __block int err;

    [coordinator coordinateReadingItemAtURL:in_url options:NSFileCoordinatorReadingWithoutChanges error:&error byAccessor:^(NSURL *url) {
        err = realfs.stat(mount, path_for_url_in_mount(mount, url, path), fake_stat, follow_links);
    }];

    return combine_error(error, err);
}

static int iosfs_fstat(struct fd *fd, struct statbuf *fake_stat) {
    int err = realfs.fstat(fd, fake_stat);
    return err;
}

static int iosfs_utime(struct mount *mount, const char *path, struct timespec atime, struct timespec mtime) {
    NSFileCoordinator *coordinator = [[NSFileCoordinator alloc] initWithFilePresenter:nil];
    NSURL *in_url = url_for_path_in_mount(mount, path);

    NSError *error;
    __block int err;

    [coordinator coordinateWritingItemAtURL:in_url options:NSFileCoordinatorWritingContentIndependentMetadataOnly error:&error byAccessor:^(NSURL *url) {
        err = realfs.utime(mount, path_for_url_in_mount(mount, url, path), atime, mtime);
    }];

    return combine_error(error, err);
}

static int iosfs_mkdir(struct mount *mount, const char *path, mode_t_ mode) {
    NSFileCoordinator *coordinator = [[NSFileCoordinator alloc] initWithFilePresenter:nil];
    NSURL *in_url = url_for_path_in_mount(mount, path);

    NSError *error;
    __block int err;

    [coordinator coordinateWritingItemAtURL:in_url options:NSFileCoordinatorWritingForCreating error:&error byAccessor:^(NSURL *url) {
        err = realfs.mkdir(mount, path_for_url_in_mount(mount, url, path), mode);
    }];

    return combine_error(error, err);
}

static int iosfs_flock(struct fd *fd, int operation) {
    return realfs.flock(fd, operation);
}

const struct fs_ops iosfs = {
    .name = "ios", .magic = 0x7265616d,
    .mount = iosfs_mount,
    .umount = iosfs_umount,
    .statfs = realfs_statfs,

    .open = iosfs_open,
    .readlink = iosfs_readlink,
    .link = iosfs_link,
    .unlink = iosfs_unlink,
    .rmdir = iosfs_rmdir,
    .rename = iosfs_rename,
    .symlink = iosfs_symlink,
    .mknod = iosfs_mknod,

    .close = iosfs_close,
    .stat = iosfs_stat,
    .fstat = iosfs_fstat,
    .setattr = iosfs_setattr,
    .fsetattr = iosfs_fsetattr,
    .utime = iosfs_utime,
    .getpath = iosfs_getpath,
    .flock = iosfs_flock,

    .mkdir = iosfs_mkdir,
};

const struct fs_ops iosfs_unsafe = {
    .name = "ios-unsafe", .magic = 0x7265616e,
    .mount = iosfs_mount,
    .umount = iosfs_umount,
    .statfs = realfs_statfs,

    .open = realfs_open,
    .readlink = realfs_readlink,
    .link = realfs_link,
    .unlink = realfs_unlink,
    .rmdir = realfs_rmdir,
    .rename = realfs_rename,
    .symlink = realfs_symlink,
    .mknod = realfs_mknod,

    .close = realfs_close,
    .stat = realfs_stat,
    .fstat = realfs_fstat,
    .setattr = realfs_setattr,
    .fsetattr = realfs_fsetattr,
    .utime = realfs_utime,
    .getpath = realfs_getpath,
    .flock = realfs_flock,

    .mkdir = realfs_mkdir,
};

const struct fd_ops iosfs_fdops = {
    .read = realfs_read,
    .write = realfs_write,
    .readdir = realfs_readdir,
    .telldir = realfs_telldir,
    .seekdir = realfs_seekdir,
    .lseek = realfs_lseek,
    .mmap = realfs_mmap,
    .poll = realfs_poll,
    .fsync = realfs_fsync,
    .close = iosfs_close,
    .getflags = realfs_getflags,
    .setflags = realfs_setflags,
};
