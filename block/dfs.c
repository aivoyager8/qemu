/*
 * QEMU Block driver for daos
 *
 * Copyright (C) 2025 ChenHonggang <c744402859@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */


#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/module.h"
#include "qemu/option.h"
#include "block/block-io.h"
#include "block/block_int.h"
#include "block/qdict.h"
#include "crypto/secret.h"
#include "qemu/cutils.h"
#include "sysemu/replay.h"
#include "qapi/qmp/qstring.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qjson.h"
#include "qapi/qmp/qlist.h"
#include "qapi/qobject-input-visitor.h"
#include "qapi/qapi-visit-block-core.h"

#include "daos.h"
#include "daos_fs.h"

/*
 * When specifying the image filename use:
 *
 * dfs:poolname/containername[@snapshotname][:option1=value1[:option2=value2...]]
 *
 * poolname must be the name of an existing daos pool.
 *
 * containername is the name of the daos container.
 */



 
static QemuOptsList qemu_rbd_create_opts = {
    .name = "rbd-create-opts",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_rbd_create_opts.head),
    .desc = {
        {
            .name = BLOCK_OPT_SIZE,
            .type = QEMU_OPT_SIZE,
            .help = "Virtual disk size"
        },
        {
            .name = BLOCK_OPT_CLUSTER_SIZE,
            .type = QEMU_OPT_SIZE,
            .help = "RBD object size"
        },
        {
            .name = "password-secret",
            .type = QEMU_OPT_STRING,
            .help = "ID of secret providing the password",
        },
        {
            .name = "encrypt.format",
            .type = QEMU_OPT_STRING,
            .help = "Encrypt the image, format choices: 'luks', 'luks2'",
        },
        {
            .name = "encrypt.cipher-alg",
            .type = QEMU_OPT_STRING,
            .help = "Name of encryption cipher algorithm"
                    " (allowed values: aes-128, aes-256)",
        },
        {
            .name = "encrypt.key-secret",
            .type = QEMU_OPT_STRING,
            .help = "ID of secret providing LUKS passphrase",
        },
        { /* end of list */ }
    }
};

static const char *const qemu_rbd_strong_runtime_opts[] = {
    "pool",
    "namespace",
    "image",
    "conf",
    "snapshot",
    "user",
    "server.",
    "password-secret",

    NULL
};

/*
static BlockDriver bdrv_rbd = {
    .format_name            = "rbd",
    .instance_size          = sizeof(BDRVRBDState),
    .bdrv_parse_filename    = qemu_rbd_parse_filename,
    .bdrv_file_open         = qemu_rbd_open,
    .bdrv_close             = qemu_rbd_close,
    .bdrv_reopen_prepare    = qemu_rbd_reopen_prepare,
    .bdrv_co_create         = qemu_rbd_co_create,
    .bdrv_co_create_opts    = qemu_rbd_co_create_opts,
    .bdrv_has_zero_init     = bdrv_has_zero_init_1,
    .bdrv_co_get_info       = qemu_rbd_co_get_info,
    .bdrv_get_specific_info = qemu_rbd_get_specific_info,
    .create_opts            = &qemu_rbd_create_opts,
    .bdrv_co_getlength      = qemu_rbd_co_getlength,
    .bdrv_co_truncate       = qemu_rbd_co_truncate,
    .protocol_name          = "rbd",

    .bdrv_co_preadv         = qemu_rbd_co_preadv,
    .bdrv_co_pwritev        = qemu_rbd_co_pwritev,
    .bdrv_co_flush_to_disk  = qemu_rbd_co_flush,
    .bdrv_co_pdiscard       = qemu_rbd_co_pdiscard,
#ifdef LIBRBD_SUPPORTS_WRITE_ZEROES
    .bdrv_co_pwrite_zeroes  = qemu_rbd_co_pwrite_zeroes,
#endif
    .bdrv_co_block_status   = qemu_rbd_co_block_status,

    .bdrv_snapshot_create   = qemu_rbd_snap_create,
    .bdrv_snapshot_delete   = qemu_rbd_snap_remove,
    .bdrv_snapshot_list     = qemu_rbd_snap_list,
    .bdrv_snapshot_goto     = qemu_rbd_snap_rollback,
    .bdrv_co_invalidate_cache = qemu_rbd_co_invalidate_cache,

    .strong_runtime_opts    = qemu_rbd_strong_runtime_opts,
};
*/

typedef struct BDRVDFSState {
    daos_handle_t pool;
    daos_handle_t container;
    dfs_t *dfs;
    dfs_obj_t *file;
    char *pool_name;
    char *container_name;
} BDRVDFSState;


/**
 * Parses the filename and extracts options for DFS block driver.
 *
 * @param filename The filename string to parse
 * @param options The dictionary to store extracted options
 * @param errp Pointer to error object
 * @return 0 on success, negative errno on failure
 */
static int qemu_dfs_parse_filename(const char *filename, QDict *options, Error **errp)
{
    char *pool_name, *container_name;
    const char *p;

    if (strncmp(filename, "dfs:", 4)) {
        return -EINVAL;
    }

    p = strchr(filename, ':');
    if (!p) {
        error_setg(errp, "Missing pool/container specification");
        return -EINVAL;
    }

    p++;
    pool_name = g_strdup(p);
    p = strchr(pool_name, '/');
    if (!p) {
        g_free(pool_name);
        error_setg(errp, "Invalid pool/container specification");
        return -EINVAL;
    }
    
    *strchr(pool_name, '/') = '\0';
    container_name = g_strdup(p + 1);
    
    qdict_put_str(options, "pool", pool_name);
    qdict_put_str(options, "container", container_name);
    
    g_free(pool_name);
    g_free(container_name);
    return 0;
}

static int qemu_dfs_open(BlockDriverState *bs, QDict *options, int flags,
                        Error **errp)
{
    BDRVDFSState *s = bs->opaque;
    const char *pool_name, *container_name;
    daos_pool_info_t pool_info;
    int rc;

    pool_name = qdict_get_str(options, "pool");
    container_name = qdict_get_str(options, "container");

    rc = daos_pool_connect(pool_name, NULL, DAOS_PC_RW, &s->pool, &pool_info, NULL);
    if (rc) {
        error_setg(errp, "Failed to connect to pool: %s", strerror(rc));
        return -rc;
    }

    rc = daos_cont_open(s->pool, container_name, DAOS_COO_RW, &s->container, NULL);
    if (rc) {
        daos_pool_disconnect(s->pool, NULL);
        error_setg(errp, "Failed to open container: %s", strerror(rc));
        return -rc;
    }

    rc = dfs_mount(s->pool, s->container, O_RDWR, &s->dfs);
    if (rc) {
        daos_cont_close(s->container, NULL);
        daos_pool_disconnect(s->pool, NULL);
        error_setg(errp, "Failed to mount DFS: %s", strerror(rc));
        return -rc;
    }

    s->pool_name = g_strdup(pool_name);
    s->container_name = g_strdup(container_name);
    return 0;
}

static void qemu_dfs_close(BlockDriverState *bs)
{
    BDRVDFSState *s = bs->opaque;

    if (s->dfs) {
        dfs_umount(s->dfs);
    }
    if (s->container.cookie) {
        daos_cont_close(s->container, NULL);
    }
    if (s->pool.cookie) {
        daos_pool_disconnect(s->pool, NULL);
    }
    g_free(s->pool_name);
    g_free(s->container_name);
}

static int coroutine_fn qemu_dfs_co_preadv(BlockDriverState *bs,
                                          int64_t offset, int64_t bytes,
                                          QEMUIOVector *qiov, int flags)
{
    BDRVDFSState *s = bs->opaque;
    ssize_t ret;

    ret = dfs_read(s->dfs, s->file, qiov->iov, qiov->niov, offset, &bytes, NULL);
    if (ret < 0) {
        return -ret;
    }
    return bytes;
}

static int coroutine_fn qemu_dfs_co_pwritev(BlockDriverState *bs,
                                           int64_t offset, int64_t bytes,
                                           QEMUIOVector *qiov, int flags)
{
    BDRVDFSState *s = bs->opaque;
    ssize_t ret;

    ret = dfs_write(s->dfs, s->file, qiov->iov, qiov->niov, offset, NULL);
    if (ret < 0) {
        return -ret;
    }
    return bytes;
}

static int64_t coroutine_fn qemu_dfs_co_getlength(BlockDriverState *bs)
{
    BDRVDFSState *s = bs->opaque;
    daos_size_t size;
    int rc;

    rc = dfs_get_size(s->dfs, s->file, &size);
    if (rc) {
        return -rc;
    }
    return size;
}



static BlockDriver bdrv_dfs = {
    .format_name            = "dfs",
    .instance_size         = sizeof(BDRVDFSState),
    .bdrv_parse_filename   = qemu_dfs_parse_filename,
    .bdrv_file_open       = qemu_dfs_open,
    .bdrv_close           = qemu_dfs_close,
    .protocol_name       = "dfs",

    .bdrv_co_preadv     = qemu_dfs_co_preadv,
    .bdrv_co_pwritev    = qemu_dfs_co_pwritev,
    .bdrv_co_getlength   = qemu_dfs_co_getlength,
};


static void bdrv_dfs_init(void)
{
    bdrv_register(&bdrv_dfs);
}

block_init(bdrv_rbd_init);
