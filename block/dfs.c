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

#include "qemu/osdep.h"
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
 * dfs:poolname/containername/filename[@snapshotname][:option1=value1[:option2=value2...]]
 *
 * poolname must be the name of an existing daos pool.
 *
 * containername is the name of the daos container.
 */

static QemuOptsList qemu_rbd_create_opts = {
    .name = "rbd-create-opts",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_rbd_create_opts.head),
    .desc = {
        {.name = BLOCK_OPT_SIZE,
         .type = QEMU_OPT_SIZE,
         .help = "Virtual disk size"},
        {.name = BLOCK_OPT_CLUSTER_SIZE,
         .type = QEMU_OPT_SIZE,
         .help = "RBD object size"},
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
        {/* end of list */}}};

// static const char *const qemu_rbd_strong_runtime_opts[] = {
//     "pool",
//     "namespace",
//     "image",
//     "conf",
//     "snapshot",
//     "user",
//     "server.",
//     "password-secret",
//     NULL
// };

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
typedef struct BDRVDFSState
{
    daos_handle_t pool;
    daos_handle_t container;
    dfs_t *dfs;
    dfs_obj_t *namespace;
    dfs_obj_t *file;
    char *pool_name;
    char *container_name;
    char *file_name;
} BDRVDFSState;

/**
 * Tokenizes a string based on a delimiter character.
 *
 * @param src   The source string to tokenize. If NULL, function returns NULL.
 * @param delim The delimiter character to split on.
 * @param p     Pointer to store the remaining string after the token.
 *              Will be set to NULL if no delimiter is found.
 *              If delimiter is found, will point to character after delimiter.
 *
 * @return The token string up to the delimiter, or the entire string if no
 *         delimiter is found. Returns NULL if src is NULL.
 *
 * @note The function modifies the original string by replacing delimiter with '\0'.
 */
static char *qemu_dfs_next_tok(char *src, char delim, char **p)
{
    char *end;

    *p = NULL;
    if (src == NULL)
    {
        return NULL;
    }

    end = strchr(src, delim);
    if (end)
    {
        *end = '\0';
        *p = end + 1;
    }
    return src;
}

/**
 * @brief Parses a DFS (Distributed File System) URL into its components
 *
 * Parses a filename in the format "dfs:pool/container/file" and stores the components
 * in the provided options dictionary.
 *
 * The format must be exactly:
 * - Start with "dfs:" prefix
 * - Followed by pool name
 * - Followed by container name
 * - Followed by file name
 * Each component separated by forward slashes.
 *
 * @param filename The DFS URL string to parse
 * @param options Dictionary to store the parsed components:
 *                - "pool": Pool name
 *                - "container": Container name
 *                - "filename": File path
 * @param errp Location to store error information
 *
 * @note The function will set an error and return early if:
 *       - The filename doesn't start with "dfs:"
 *       - Pool name is missing or empty
 *       - Container name is missing or empty
 *       - File name is missing or empty
 */
static void qemu_dfs_parse_filename(const char *filename, QDict *options, Error **errp)
{
    const char *start;
    char *p, *buf;
    char *pool, *container, *file;

    if (!strstart(filename, "dfs:", &start))
    {
        error_setg(errp, "Filename must start with 'dfs:'");
        return;
    }

    buf = g_strdup(start);
    p = buf;

    // 解析 pool
    pool = qemu_dfs_next_tok(p, '/', &p);
    if (!pool || !*pool)
    {
        error_setg(errp, "Pool name must be specified");
        goto done;
    }
    qdict_put_str(options, "pool", pool);
    const char *poolname = qdict_get_str(options, "pool");
    if (!poolname)
    {
        error_setg(errp, "pool option not found");
        goto done;
    }

    // 解析 container
    container = qemu_dfs_next_tok(p, '/', &p);
    if (!container || !*container)
    {
        error_setg(errp, "Container name must be specified");
        goto done;
    }
    qdict_put_str(options, "container", container);
    // 解析 file
    file = p;
    if (!file || !*file)
    {
        error_setg(errp, "File name must be specified");
        goto done;
    }
    qdict_put_str(options, "dfilename", file);
    qdict_put_str(options, "filename", filename);

done:
    g_free(buf);
}

/**
 * Converts QDict options to DFS blockdev options structure.
 *
 * @param options QDict containing the block device options
 * @param opts    Pointer to pointer to BlockdevOptionsDFS structure that will be allocated and filled
 * @param errp    Error object to store error information
 *
 * @return 0 on success, negative errno on failure
 */
static int qemu_dfs_convert_options(QDict *options, BlockdevOptionsDFS **opts,
                                    Error **errp)
{
    Visitor *v;
    /* Convert the remaining options into a QAPI object */
    v = qobject_input_visitor_new_flat_confused(options, errp);
    if (!v)
    {
        return -EINVAL;
    }

    visit_type_BlockdevOptionsDFS(v, NULL, opts, errp);
    visit_free(v);
    if (!opts)
    {
        return -EINVAL;
    }
    return 0;
}

#define DEFAULT_NS "xblock" // 默认的NameSpace
static int qemu_dfs_open(BlockDriverState *bs, QDict *options, int flags,
                         Error **errp)
{
    int rc;
    BDRVDFSState *s = bs->opaque;
    BlockdevOptionsDFS *opts = NULL;
    Error *local_err = NULL;
    const QDictEntry *e;

    rc = qemu_dfs_convert_options(options, &opts, &local_err);
    if (local_err)
    {
        error_propagate(errp, local_err);
        return rc;
    }

    if (opts == NULL)
    {
        error_setg(errp, "Failed to convert options");
        goto err;
    }

    if (opts->pool == NULL || opts->container == NULL || opts->dfilename == NULL)
    {
        error_setg(errp, "Missing pool, container or filename");
        goto err;
    }

    // 获取pool/container/file信息
    s->pool_name = g_strdup(opts->pool);
    s->container_name = g_strdup(opts->container);
    s->file_name = g_strdup(opts->dfilename);

    while ((e = qdict_first(options))) {
        qdict_del(options, e->key);
    }


    // 初始化DFS
    rc = dfs_init();
    if (rc)
    {
        error_setg(errp, "Failed to initialize DFS: %d", rc);
        goto err;
    }

    // dfs_connect(const char *pool, const char *sys, const char *cont, int flags, dfs_attr_t *attr,  dfs_t **_dfs)
    rc = dfs_connect(s->pool_name, NULL, s->container_name, O_CREAT | O_RDWR, NULL, &s->dfs);
    if (rc)
    {
        error_setg(errp, "Failed to connect to pool %s container %s: %d",
                   s->pool_name, s->container_name, rc);
        goto err;
    }

    // 打开一个默认的NameSpace, 用于存储文件.
    mode_t ns_mode = S_IWUSR | S_IRUSR | S_IFDIR;
    int ns_flags = O_RDWR | O_CREAT; // 假设没有创建接口. 这里先一起处理吧.
    rc = dfs_open(s->dfs, NULL, DEFAULT_NS, ns_mode, ns_flags, 0, 0, NULL, &s->namespace);
    if (rc)
    {
        error_setg(errp, "Failed to open container %s: %d", s->container_name, rc);
        goto err;
    }

    // 在默认的NameSpace下创建一个文件.
    rc = dfs_open(s->dfs, s->namespace, s->file_name, S_IWUSR | S_IRUSR | S_IFREG, O_RDWR | O_CREAT, 0, 0, NULL, &s->file);
    if (rc)
    {
        error_setg(errp, "Failed to open file %s: %d", s->file_name, rc);
        goto err;
    }

    // 释放资源
    if (opts)
    {
        qapi_free_BlockdevOptionsDFS(opts);
    }
    return 0;

err:
    if (opts)
    {
        qapi_free_BlockdevOptionsDFS(opts);
    }

    if (s->namespace)
    {
        dfs_release(s->namespace);
    }

    if (s->dfs)
    {
        dfs_disconnect(s->dfs);
    }

    return rc;
}

/**
 * Closes a DFS block device.
 *
 * This function handles the cleanup and release of resources associated with
 * a DFS (Distributed File System) block device when it is being closed.
 *
 * @param bs    Pointer to the BlockDriverState structure representing the block device
 */
static void qemu_dfs_close(BlockDriverState *bs)
{
    BDRVDFSState *s = bs->opaque;

    if (s->file)
    {
        dfs_release(s->file);
    }

    if (s->namespace)
    {
        dfs_release(s->namespace);
    }

    if (s->dfs)
    {
        dfs_disconnect(s->dfs);
    }

    if (s->file_name)
    {
        g_free(s->file_name);
    }

    if (s->container_name)
    {
        g_free(s->container_name);
    }

    if (s->pool_name)
    {
        g_free(s->pool_name);
    }
}


/**
 * Converts a QEMU I/O vector to a DFS scatter-gather list.
 *
 * Translates the memory regions described in the QEMU I/O vector to
 * the format required by the DFS scatter-gather list structure.
 *
 * @param qiov      Pointer to the QEMU I/O vector to convert
 * @param sg_list   Pointer to the DFS scatter-gather list to populate
 *
 * @return 0 on success, negative errno on failure
 * @retval -1 Memory allocation failure
 * NOTE: This function allocates memory for the scatter-gather list.
 *         The caller is responsible for freeing the memory.
 */
static int qiov_to_sg_list(QEMUIOVector *qiov, d_sg_list_t *sg_list)
{
    int i;
    uint64_t total_size = 0;

    // 1. 计算总大小
    for (i = 0; i < qiov->niov; i++) {
        total_size += qiov->iov[i].iov_len;
    }
    
    if (total_size == 0) {
        error_setg(&error_abort, "QEMU I/O vector is empty");
        return -EINVAL;
    }

    // 2. 分配 sg_list
    sg_list->sg_nr = qiov->niov;
    sg_list->sg_nr_out = 0;
    sg_list->sg_iovs = calloc(qiov->niov, sizeof(*sg_list->sg_iovs));
    if (!sg_list->sg_iovs) {
        return -ENOMEM;
    }

    // 3. 复制 IOV
    for (i = 0; i < qiov->niov; i++) {
        sg_list->sg_iovs[i].iov_buf = qiov->iov[i].iov_base;
        sg_list->sg_iovs[i].iov_buf_len = qiov->iov[i].iov_len;
        sg_list->sg_iovs[i].iov_len = qiov->iov[i].iov_len;
    }

    return 0;
}

/**
 * Read data from the file object, and return actual data read.
 *
 * \param[in]	dfs	Pointer to the mounted file system.
 * \param[in]	obj	Opened file object.
 * \param[in]	sgl	Scatter/Gather list for data buffer.
 * \param[in]	off	Offset into the file to read from.
 * \param[out]	read_size
 *			How much data is actually read.
 * \param[in]	ev	Completion event, it is optional and can be NULL.
 *			Function will run in blocking mode if \a ev is NULL.
 *
 * \return		0 on success, errno code on failure.
 */
static int coroutine_fn qemu_dfs_co_preadv(BlockDriverState *bs,
                                           int64_t offset, int64_t bytes,
                                           QEMUIOVector *qiov,
                                           BdrvRequestFlags flags)
{
    int rc;
    BDRVDFSState *s = bs->opaque;
    daos_size_t read_size;
    assert(!qiov || qiov->size == bytes);

    d_sg_list_t sgl;
    rc = qiov_to_sg_list(qiov, &sgl);
    if (rc)
    {
        error_setg(&error_abort, "Failed to convert QEMU I/O vector to DFS scatter-gather list");
        return rc;
    }

    // 读取文件
    rc = dfs_read(s->dfs, s->file, &sgl, offset, &read_size, NULL);
    if (rc)
    {
        error_setg(&error_abort, "Failed to read from DFS file");
    }

    free(sgl.sg_iovs);
    return read_size;
}

/**
 * Write data to the file object, and return actual data written.
 *
 * \param[in]	dfs	Pointer to the mounted file system.
 * \param[in]	obj	Opened file object.
 * \param[in]	sgl	Scatter/Gather list for data buffer.
 * \param[in]	off	Offset into the file to write to.
 * \param[out]	written_size
 *			How much data is actually written.
 * \param[in]	ev	Completion event, it is optional and can be NULL.
 *			Function will run in blocking mode if \a ev is NULL.
 *
 * \return		0 on success, errno code on failure.
 */
static int coroutine_fn qemu_dfs_co_pwritev(BlockDriverState *bs,
                                            int64_t offset, int64_t bytes,
                                            QEMUIOVector *qiov,
                                            BdrvRequestFlags flags)
{
    int rc;
    BDRVDFSState *s = bs->opaque;
    assert(!qiov || qiov->size == bytes);

    d_sg_list_t sgl;
    rc = qiov_to_sg_list(qiov, &sgl);
    if (rc)
    {
        error_setg(&error_abort, "Failed to convert QEMU I/O vector to DFS scatter-gather list");
        return rc;
    }

    // 写入文件
    rc = dfs_write(s->dfs, s->file, &sgl, offset, NULL);
    if (rc)
    {
        error_setg(&error_abort, "Failed to write to DFS file");
    }
    free(sgl.sg_iovs);
    return rc;
}

/**
 * Gets the length of a DFS (Distributed File System) block device.
 *
 * This is a coroutine function that returns the total size of the block device
 * in bytes.
 *
 * @param bs    Block driver state
 * @return      The length of the block device in bytes, or negative errno on failure
 */
static int64_t coroutine_fn qemu_dfs_co_getlength(BlockDriverState *bs)
{
    int rc;
    BDRVDFSState *s = bs->opaque;
    size_t size;

    if (!s->file || !s->dfs)
    {
        error_setg(&error_abort, "DFS file not open");
        return -ENOENT;
    }

    // 获取文件大小
    rc = dfs_get_size(s->dfs, s->file, &size);
    if (rc)
    {
        return rc;
    }
    return size;
}


static const char *const qemu_dfs_runtime_opts[] = {
    "pool",
    "container", 
    "dfilename",
    NULL
};



static BlockDriver bdrv_dfs = {
    .format_name = "dfs",
    .instance_size = sizeof(BDRVDFSState),
    .bdrv_parse_filename = qemu_dfs_parse_filename,
    .bdrv_file_open = qemu_dfs_open,
    .bdrv_close = qemu_dfs_close,
    .protocol_name = "dfs",

    .bdrv_co_preadv = qemu_dfs_co_preadv,
    .bdrv_co_pwritev = qemu_dfs_co_pwritev,
    .bdrv_co_getlength = qemu_dfs_co_getlength,

    .strong_runtime_opts = qemu_dfs_runtime_opts,
};

static void bdrv_dfs_init(void)
{
    bdrv_register(&bdrv_dfs);
}

block_init(bdrv_dfs_init);
