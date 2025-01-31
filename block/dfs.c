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

#define DEFAULT_NS "xblock" // 默认的数据目录名称

/**
 * When specifying the image filename use:
 *
 * dfs:poolname/containername/filename[@snapshotname][:option1=value1[:option2=value2...]]
 *
 * poolname must be the name of an existing daos pool.
 *
 * containername is the name of the daos container.
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
    /* Validate input parameters */
    if (!p) {
        return NULL;
    }

    *p = NULL;

    if (!src) {
        return NULL;
    }

    /* Find delimiter and split string */
    char *end = strchr(src, delim);
    if (end) {
        /* Only modify the string if we found the delimiter */
        *end = '\0';
        *p = end + 1;
    }

    /* Return start of token */
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
    char *buf = NULL;
    const char *start;
    char *next_ptr = NULL;
    char *pool_name = NULL; 
    char *container_name = NULL;
    char *file_name = NULL;

    /* Validate input parameters */
    if (!filename || !options || !errp) {
        error_setg(errp, "Invalid parameters");
        return;
    }

    /* Check prefix */
    if (!strstart(filename, "dfs:", &start)) {
        error_setg(errp, "Filename must start with 'dfs:'");
        return;
    }

    /* Skip empty path after prefix */
    if (!*start) {
        error_setg(errp, "Empty path after dfs: prefix");
        return;
    }

    /* Duplicate string for tokenization */
    buf = g_strdup(start);
    if (!buf) {
        error_setg(errp, "Memory allocation failed");
        return;
    }

    /* Parse pool name */
    pool_name = qemu_dfs_next_tok(buf, '/', &next_ptr);
    if (!pool_name || !*pool_name) {
        error_setg(errp, "Pool name must be specified");
        goto cleanup;
    }

    /* Parse container name */
    container_name = qemu_dfs_next_tok(next_ptr, '/', &next_ptr);
    if (!container_name || !*container_name) {
        error_setg(errp, "Container name must be specified");
        goto cleanup;
    }

    /* Parse file name - everything after the second slash */
    file_name = next_ptr;
    if (!file_name || !*file_name) {
        error_setg(errp, "File name must be specified");
        goto cleanup;
    }

    /* Store values in options dictionary */
    if (!qdict_haskey(options, "pool")) {
        qdict_put_str(options, "pool", pool_name);
    }
    if (!qdict_haskey(options, "container")) {
        qdict_put_str(options, "container", container_name);
    }
    if (!qdict_haskey(options, "dfilename")) {
        qdict_put_str(options, "dfilename", file_name);
    }
    if (!qdict_haskey(options, "filename")) {
        qdict_put_str(options, "filename", filename);
    }

    /* Verify all required options are present */
    if (!qdict_get_try_str(options, "pool") ||
        !qdict_get_try_str(options, "container") ||
        !qdict_get_try_str(options, "dfilename")) {
        error_setg(errp, "Failed to store required options");
        goto cleanup;
    }

cleanup:
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

/**
 * Opens a DFS block device.
 *
 * This function initializes and connects to a DFS (Distributed File System) block device.
 *
 * @param bs      Pointer to the BlockDriverState structure representing the block device
 * @param options QDict containing the block device options
 * @param flags   Flags to control the behavior of the block device
 * @param errp    Error object to store error information
 *
 * @return 0 on success, negative errno on failure
 */
static int qemu_dfs_open(BlockDriverState *bs, QDict *options, int flags,
                         Error **errp)
{
    int rc;
    BDRVDFSState *s;
    BlockdevOptionsDFS *opts = NULL;
    Error *local_err = NULL;
    const QDictEntry *e;

    if (!bs || !options || !errp) {
        return -EINVAL;
    }

    s = bs->opaque;
    if (!s) {
        error_setg(errp, "Invalid block driver state");
        return -EINVAL;
    }

    // Initialize state to NULL
    s->pool_name = NULL;
    s->container_name = NULL;
    s->file_name = NULL;
    s->dfs = NULL;
    s->namespace = NULL;
    s->file = NULL;

    // Convert options and validate
    rc = qemu_dfs_convert_options(options, &opts, &local_err);
    if (rc || local_err) {
        if (local_err) {
            error_propagate(errp, local_err);
        }
        return rc ? rc : -EINVAL;
    }

    if (!opts || !opts->pool || !opts->container || !opts->dfilename) {
        error_setg(errp, "Missing required options (pool, container, or filename)");
        rc = -EINVAL;
        goto err;
    }

    // Store path components with null checks
    s->pool_name = g_strdup(opts->pool);
    s->container_name = g_strdup(opts->container);
    s->file_name = g_strdup(opts->dfilename);

    if (!s->pool_name || !s->container_name || !s->file_name) {
        error_setg(errp, "Failed to allocate path strings");
        rc = -ENOMEM;
        goto err;
    }

    // Clear processed options safely
    if (options) {
        while ((e = qdict_first(options))) {
            qdict_del(options, e->key);
        }
    }

    // Initialize DFS subsystem
    rc = dfs_init();
    if (rc) {
        error_setg(errp, "Failed to initialize DFS: %d", rc);
        goto err;
    }

    // Connect to DFS pool/container
    rc = dfs_connect(s->pool_name, NULL, s->container_name, 
                     O_CREAT | O_RDWR, NULL, &s->dfs);
    if (rc || !s->dfs) {
        error_setg(errp, "Failed to connect to pool %s container %s: %d",
                   s->pool_name, s->container_name, rc);
        goto err;
    }

    // Open/create default namespace
    rc = dfs_open(s->dfs, NULL, DEFAULT_NS,
                  S_IWUSR | S_IRUSR | S_IFDIR,  // Mode
                  O_RDWR,             // Flags
                  0, 0, NULL, &s->namespace);
    if (rc || !s->namespace) {
        error_setg(errp, "Failed to open namespace %s: %d", 
                   DEFAULT_NS, rc);
        goto err;
    }

    // Open/create file within namespace
    rc = dfs_open(s->dfs, s->namespace, s->file_name,
                  S_IWUSR | S_IRUSR | S_IFREG,  // Mode 
                  O_RDWR,                        // Flags - removed O_CREAT
                  0, 0, NULL, &s->file);
    if (rc || !s->file) {
        error_setg(errp, "Failed to open file %s: %d", 
                   s->file_name, rc);
        goto err;
    }

    qapi_free_BlockdevOptionsDFS(opts);
    return 0;

err:
    // Clean up in reverse order of creation
    if (s->file) {
        dfs_release(s->file);
        s->file = NULL;
    }
    
    if (s->namespace) {
        dfs_release(s->namespace);
        s->namespace = NULL;
    }
    
    if (s->dfs) {
        dfs_disconnect(s->dfs);
        s->dfs = NULL;
        dfs_fini(); // Clean up DFS subsystem
    }

    g_free(s->file_name);
    g_free(s->container_name); 
    g_free(s->pool_name);
    s->file_name = NULL;
    s->container_name = NULL;
    s->pool_name = NULL;

    if (opts) {
        qapi_free_BlockdevOptionsDFS(opts);
    }
    
    return rc ? rc : -EIO;
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
 * @param qiov      Source QEMU I/O vector to convert
 * @param sg_list   Target DFS scatter-gather list to populate
 *
 * @return 0 on success, negative errno on failure
 *
 * @note The caller must free sg_list->sg_iovs after use
 */
static int qiov_to_sg_list(const QEMUIOVector *qiov, d_sg_list_t *sg_list)
{
    int ret = 0;
    uint64_t total_size = 0;

    if (!qiov || !sg_list) {
        return -EINVAL;
    }

    if (qiov->niov == 0 || !qiov->iov) {
        return -EINVAL;
    }

    /* Initialize sg_list to safe values */
    memset(sg_list, 0, sizeof(*sg_list));

    /* Calculate total size and validate iov entries */
    for (int i = 0; i < qiov->niov; i++) {
        if (!qiov->iov[i].iov_base && qiov->iov[i].iov_len > 0) {
            return -EINVAL;
        }
        
        /* Check for overflow */
        if (total_size + qiov->iov[i].iov_len < total_size) {
            return -EOVERFLOW;
        }
        total_size += qiov->iov[i].iov_len;
    }

    if (total_size == 0) {
        return -EINVAL;
    }

    /* Allocate sg_iovs array */
    sg_list->sg_iovs = calloc(qiov->niov, sizeof(*sg_list->sg_iovs));
    if (!sg_list->sg_iovs) {
        return -ENOMEM;
    }

    /* Copy IOV entries */
    sg_list->sg_nr = qiov->niov;
    sg_list->sg_nr_out = 0;

    for (int i = 0; i < qiov->niov; i++) {
        sg_list->sg_iovs[i].iov_buf = qiov->iov[i].iov_base;
        sg_list->sg_iovs[i].iov_buf_len = qiov->iov[i].iov_len;
        sg_list->sg_iovs[i].iov_len = qiov->iov[i].iov_len;
    }

    return ret;
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
    int rc = 0;
    BDRVDFSState *s;
    daos_size_t read_size = 0;
    d_sg_list_t sgl = {0};

    /* Parameter validation */
    if (!bs || !qiov) {
        return -EINVAL;
    }

    s = bs->opaque;
    if (!s || !s->dfs || !s->file) {
        return -ENOENT;
    }

    /* Validate offset and size */
    if (offset < 0 || bytes < 0) {
        return -EINVAL;
    }

    /* Verify qiov size matches bytes requested */
    if (qiov->size != bytes) {
        return -EINVAL;
    }

    /* Convert QEMU I/O vector to DFS scatter-gather list */
    rc = qiov_to_sg_list(qiov, &sgl);
    if (rc) {
        error_setg(&error_abort, "Failed to convert I/O vector: %d", rc);
        return rc;
    }

    /* Read from file */
    rc = dfs_read(s->dfs, s->file, &sgl, offset, &read_size, NULL);
    if (rc) {
        error_setg(&error_abort, "DFS read failed (rc=%d): %s", 
                  rc, strerror(abs(rc)));
        free(sgl.sg_iovs);
        return rc;
    }

    /* Check if we read the expected amount */
    if (read_size != bytes) {
        /* Not necessarily an error - could be EOF */
        info_report("Partial read: expected %"PRId64" bytes, got %zu", 
                   bytes, read_size); 
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
    int rc = 0;
    BDRVDFSState *s;
    daos_size_t written_size = 0;
    d_sg_list_t sgl = {0};

    /* Parameter validation */
    if (!bs || !qiov) {
        return -EINVAL;
    }

    s = bs->opaque;
    if (!s || !s->dfs || !s->file) {
        return -ENOENT;
    }

    /* Validate offset and size */
    if (offset < 0 || bytes < 0) {
        return -EINVAL;
    }

    /* Verify qiov size matches bytes requested */
    if (qiov->size != bytes) {
        return -EINVAL;
    }

    /* Convert QEMU I/O vector to DFS scatter-gather list */
    rc = qiov_to_sg_list(qiov, &sgl);
    if (rc) {
        error_setg(&error_abort, "Failed to convert I/O vector: %d", rc);
        return rc;
    }

    /* Write to file */
    rc = dfs_write(s->dfs, s->file, &sgl, offset, NULL);
    if (rc) {
        error_setg(&error_abort, "DFS write failed (rc=%d): %s",
                  rc, strerror(abs(rc)));
        free(sgl.sg_iovs);
        return rc;
    }

    /* Check if we wrote the expected amount */
    if (written_size != bytes) {
        error_setg(&error_abort, "Partial write: expected %"PRId64" bytes, wrote %zu",
                  bytes, written_size);
        free(sgl.sg_iovs);
        return -EIO;
    }

    free(sgl.sg_iovs);
    return written_size;
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
    BDRVDFSState *s;
    daos_size_t size;

    /* Parameter validation */
    if (!bs) {
        error_setg(&error_abort, "Invalid block driver state");
        return -EINVAL; 
    }

    s = bs->opaque;
    if (!s) {
        error_setg(&error_abort, "Invalid block driver opaque state");
        return -EINVAL;
    }

    if (!s->dfs || !s->file) {
        error_setg(&error_abort, "DFS file not open");
        return -ENOENT;
    }

    /* Get file size */
    rc = dfs_get_size(s->dfs, s->file, &size);
    if (rc) {
        error_setg(&error_abort, "Failed to get DFS file size: %d", rc);
        return rc;
    }

    /* Check for valid size */
    if (size > INT64_MAX) {
        error_setg(&error_abort, "Invalid file size: %zu", size);
        return -EOVERFLOW;
    }

    return size;
}

/**
 * Truncates a DFS (Distributed File System) block device.
 *
 * This function truncates the file to the specified size.
 *
 * @param dfs     DFS filesystem handle
 * @param file    DFS file object
 * @param offset  Offset to truncate the file to
 * @param errp    Error object to store any error that occurs
 *
 * @return 0 on success, negative errno on failure
 */
/**
 * Truncates a DFS file to the specified size.
 *
 * @param dfs     DFS filesystem handle
 * @param file    DFS file object handle 
 * @param offset  New size for the file
 * @param errp    Error object for reporting errors
 *
 * @return 0 on success, negative errno on failure
 *
 * @note This function validates all input parameters and uses safe error reporting.
 *       It ensures the offset is non-negative before truncating.
 */
static int qemu_dfs_do_truncate(dfs_t *dfs, dfs_obj_t *file, int64_t offset, Error **errp)
{
    int rc;

    /* Validate input parameters */
    if (!errp) {
        return -EINVAL;
    }

    if (!dfs || !file) {
        error_setg(errp, "Invalid DFS handle or file object");
        return -ENOENT;
    }

    /* Validate offset */
    if (offset < 0) {
        error_setg(errp, "Invalid negative offset: %"PRId64, offset);
        return -EINVAL;
    }

    /* Check for overflow */
    if (offset > DFS_MAX_FSIZE) {
        error_setg(errp, "Offset %"PRId64" exceeds maximum file size", offset);
        return -EFBIG;
    }

    /* Attempt to truncate the file */
    rc = dfs_punch(dfs, file, offset, DFS_MAX_FSIZE);
    if (rc != 0) {
        error_setg(errp, "Failed to truncate file (rc=%d): %s", 
                  rc, strerror(abs(rc)));
        return rc;
    }

    /* Sync changes to ensure durability */
    rc = dfs_sync(dfs);
    if (rc != 0) {
        error_setg(errp, "Failed to sync file after truncate (rc=%d): %s",
                  rc, strerror(abs(rc)));
        return rc;
    }

    return 0;
}

/**
 * Truncates a DFS (Distributed File System) block device.
 *
 * This function truncates the file to the specified size.
 *
 * @param bs      Block driver state
 * @param offset  Offset to truncate the file to
 * @param exact   If true, truncate the file to exactly the specified size
 * @param prealloc Preallocation mode
 * @param flags   Block device request flags
 * @param errp    Error object to store any error that occurs
 *
 * @return 0 on success, negative errno on failure
 */
static int coroutine_fn qemu_dfs_co_truncate(BlockDriverState *bs,
                                             int64_t offset, bool exact,
                                             PreallocMode prealloc,
                                             BdrvRequestFlags flags,
                                             Error **errp)
{
    int rc;
    BDRVDFSState *s;

    if (!bs) {
        error_setg(errp, "Invalid block driver state");
        return -EINVAL;
    }

    s = bs->opaque;
    if (!s) {
        error_setg(errp, "Invalid block driver opaque state");
        return -EINVAL;
    }

    if (!s->dfs || !s->file) {
        error_setg(errp, "DFS file not open");
        return -ENOENT;
    }

    /* Validate offset */
    if (offset < 0) {
        error_setg(errp, "Invalid negative offset: %"PRId64, offset);
        return -EINVAL;
    }

    /* Check if exact size is required but preallocation is also requested */
    if (exact && prealloc != PREALLOC_MODE_OFF) {
        error_setg(errp, "Cannot combine exact size with preallocation");
        return -EINVAL;
    }

    /* Truncate file with validated parameters */
    rc = qemu_dfs_do_truncate(s->dfs, s->file, offset, errp);
    if (rc) {
        /* Error already set by qemu_dfs_do_truncate */
        return rc;
    }

    return 0;
}

/**
 * Creates a new DFS (Distributed File System) block device.
 *
 * @param options         Creation options for the block device
 * @param keypairs       Key-value pairs for additional configuration (unused)
 * @param password_secret Password secret for encrypted devices (unused)
 * @param errp           Error object to store any error that occurs
 *
 * @return 0 on success, negative errno on failure
 */
static int qemu_dfs_do_create(BlockdevCreateOptions *options,
                              const char *keypairs,
                              const char *password_secret,
                              Error **errp)
{
    int rc = -EINVAL;
    dfs_t *dfs = NULL;
    dfs_obj_t *namespace = NULL;
    dfs_obj_t *file = NULL;
    uint64_t chunk_size = 0; // default chunk size 1MB

    // Parameter validation
    if (!options || !errp)
    {
        error_setg(errp, "Invalid parameters");
        return -EINVAL;
    }

    if (options->driver != BLOCKDEV_DRIVER_DFS)
    {
        error_setg(errp, "Invalid driver type");
        return -EINVAL;
    }

    BlockdevCreateOptionsDFS *opts = &options->u.dfs;
    if (!opts->location)
    {
        error_setg(errp, "Missing location options");
        return -EINVAL;
    }

    const char *pool = opts->location->pool;
    const char *container = opts->location->container;
    const char *filename = opts->location->dfilename;

    if (!pool || !container || !filename)
    {
        error_setg(errp, "Missing pool, container or filename");
        return -EINVAL;
    }

    // Set chunk size if provided
    if (opts->has_chunk_size)
    {
        chunk_size = opts->chunk_size;
    }

    info_report("DFS Create: pool=%s container=%s file=%s chunk_size=%lu",
                pool, container, filename, chunk_size);


    // Initialize DFS
    rc = dfs_init();
    if (rc != 0)
    {
        error_setg(errp, "Failed to initialize DFS: %d", rc);
        return rc;
    }

    // Connect to DFS
    rc = dfs_connect(pool, NULL, container, O_CREAT | O_RDWR, NULL, &dfs);
    if (rc != 0 || !dfs)
    {
        error_setg(errp, "Failed to connect to pool %s container %s: %d",
                   pool, container, rc);
        goto cleanup;
    }

    // Create/open namespace
    rc = dfs_open(dfs, NULL, DEFAULT_NS,
                  S_IWUSR | S_IRUSR | S_IFDIR, // Mode
                  O_RDWR | O_CREAT,            // Flags
                  0, 0, NULL, &namespace);
    if (rc != 0 || !namespace)
    {
        error_setg(errp, "Failed to open namespace %s: %d", DEFAULT_NS, rc);
        goto cleanup;
    }

    // Create file with exclusive flag
    rc = dfs_open(dfs, namespace, filename,
                  S_IWUSR | S_IRUSR | S_IFREG, // Mode
                  O_RDWR | O_CREAT | O_EXCL,   // Flags
                  0, 0, NULL, &file);
    if (rc != 0 || !file)
    {
        error_setg(errp, "Failed to create file %s: %d", filename, rc);
        goto cleanup;
    }

    // Truncate file to the specified size
    if (opts->size > 0)
    {
        rc = qemu_dfs_do_truncate(dfs, file, opts->size, errp);
        if (rc != 0)
        {
            error_setg(errp, "Failed to truncate file %s to size %" PRId64 ": %d",
                       filename, opts->size, rc);
            goto cleanup;
        }

        // Sync after truncate to ensure durability
        rc = dfs_sync(dfs);
        if (rc != 0)
        {
            error_setg(errp, "Failed to sync file after truncate: %d", rc);
            goto cleanup;
        }
    }

    rc = 0; // Success

cleanup:
    if (file)
    {
        dfs_release(file);
        file = NULL;
    }
    if (namespace)
    {
        dfs_release(namespace);
        namespace = NULL;
    }
    if (dfs)
    {
        dfs_disconnect(dfs);
        dfs = NULL;
    }
    dfs_fini();

    return rc;
}

/**
 * Creates a new DFS (Distributed File System) block device.
 *
 * @param options   Pointer to BlockdevCreateOptions structure containing
 *                 the parameters for creating the DFS block device
 * @param errp     Pointer to Error structure for error reporting
 *
 * @return 0 on success, negative error code on failure
 */
static int qemu_dfs_co_create(BlockdevCreateOptions *options, Error **errp)
{
    return qemu_dfs_do_create(options, NULL, NULL, errp);
}

/**
 * Parses the filename and extracts the encryption options for a new DFS file.
 *
 **/
static QemuOptsList qemu_dfs_create_opts = {
    .name = "dfs-create-opts",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_dfs_create_opts.head),
    .desc = {
        {.name = BLOCK_OPT_SIZE,
         .type = QEMU_OPT_SIZE,
         .help = "Virtual disk size"},
        {.name = BLOCK_OPT_OBJECT_SIZE,
         .type = QEMU_OPT_SIZE,
         .help = "DFS chunk size"},
    }};

// /**
//  * Creates a new disk image with specified options using DFS (Distributed File System).
//  *
//  * @param drv       Block driver instance
//  * @param filename  Path to the disk image file to be created
//  * @param opts      Creation options for the new disk image
//  * @param errp      Error object to store any error that occurs during creation
//  *
//  * @return 0 on success, negative errno on failure
//  *
//  * This is a coroutine function that handles the creation of a new disk image
//  * in the DFS storage backend with the specified parameters and options.
//  */
static int coroutine_fn qemu_dfs_co_create_opts(BlockDriver *drv,
                                                const char *filename,
                                                QemuOpts *opts,
                                                Error **errp)
{
    BlockdevCreateOptions *create_options = NULL;
    BlockdevCreateOptionsDFS *dfs_opts;
    BlockdevOptionsDFS *loc;
    QDict *options = NULL;
    int ret = -EINVAL;
    const char *pool, *container, *dfilename;

    create_options = g_new0(BlockdevCreateOptions, 1);
    if (!create_options)
    {
        error_setg(errp, "Failed to allocate create options");
        return -ENOMEM;
    }

    create_options->driver = BLOCKDEV_DRIVER_DFS;
    dfs_opts = &create_options->u.dfs;

    dfs_opts->location = g_new0(BlockdevOptionsDFS, 1);
    if (!dfs_opts->location)
    {
        error_setg(errp, "Failed to allocate location options");
        ret = -ENOMEM;
        goto exit;
    }

    dfs_opts->size = ROUND_UP(qemu_opt_get_size_del(opts, BLOCK_OPT_SIZE, 0),
                              BDRV_SECTOR_SIZE);
    dfs_opts->chunk_size = qemu_opt_get_size_del(opts, BLOCK_OPT_OBJECT_SIZE, 0);
    dfs_opts->has_chunk_size = (dfs_opts->chunk_size != 0);

    options = qdict_new();
    if (!options)
    {
        error_setg(errp, "Failed to allocate options dictionary");
        ret = -ENOMEM;
        goto exit;
    }

    qemu_dfs_parse_filename(filename, options, errp);
    if (*errp)
    {
        goto exit;
    }

    loc = dfs_opts->location;
    pool = qdict_get_try_str(options, "pool");
    container = qdict_get_try_str(options, "container");
    dfilename = qdict_get_try_str(options, "dfilename");

    if (!pool || !container || !dfilename)
    {
        error_setg(errp, "Missing required options (pool, container, or filename)");
        goto exit;
    }

    loc->pool = g_strdup(pool);
    loc->container = g_strdup(container);
    loc->dfilename = g_strdup(dfilename);

    if (!loc->pool || !loc->container || !loc->dfilename)
    {
        error_setg(errp, "Failed to allocate strings for location");
        ret = -ENOMEM;
        goto exit;
    }

    ret = qemu_dfs_do_create(create_options, NULL, NULL, errp);

exit:
    qobject_unref(options);
    qapi_free_BlockdevCreateOptions(create_options);
    return ret;
}

/**
 * Runtime options for the DFS block driver.
 */
static const char *const qemu_dfs_runtime_opts[] = {
    "pool",
    "container",
    "dfilename",
    NULL
};


/**
 * Flushes the RBD (RADOS Block Device) block driver state.
 * 
 * This coroutine function ensures all pending writes are committed to storage
 * for the given block device state.
 * 
 * @param bs    Pointer to the block driver state
 * @return      0 on success, negative errno on failure
 */
static int coroutine_fn qemu_dfs_co_flush(BlockDriverState *bs)
{
    int rc;
    BDRVDFSState *s;

    /* Parameter validation */
    if (!bs) {
        return -EINVAL;
    }

    s = bs->opaque;
    if (!s || !s->dfs || !s->file) {
        error_setg(&error_abort, "Invalid DFS state");
        return -ENOENT;
    }

    /* Sync file first for file-level durability */
    rc = dfs_sync(s->dfs); 
    if (rc) {
        error_setg(&error_abort, "DFS sync failed (rc=%d): %s",
                  rc, strerror(abs(rc)));
        return rc;
    }

    return 0;
}

/**
 * Starts a coroutine to discard data from a DFS (Distributed File System) block device.
 *
 * This coroutine function discards the specified range of data from the block device.
 *
 * @param bs     Pointer to the block driver state
 * @param offset Offset within the block device to start discarding data
 * @param bytes  Number of bytes to discard
 * @return       0 on success, negative errno on failure
 */
static int coroutine_fn qemu_dfs_co_pdiscard(BlockDriverState *bs,
                                             int64_t offset, int64_t bytes)
{
    BDRVDFSState *s;
    daos_size_t size;
    int rc;

    /* Fast path validation */
    if (!bs || offset < 0 || bytes <= 0) {
        return -EINVAL;
    }

    s = bs->opaque;
    if (!s || !s->dfs || !s->file) {
        return -ENOENT; 
    }

    /* Check for overflow */
    if (offset + bytes < offset) {
        return -EINVAL;
    }

    /* Get current file size */
    rc = dfs_get_size(s->dfs, s->file, &size);
    if (rc) {
        return rc;
    }

    /* Fast path - nothing to discard if beyond EOF */
    if (offset >= size) {
        return 0;
    }

    /* Adjust bytes if needed */
    if (offset + bytes > size) {
        bytes = size - offset;
    }

    /* Perform discard */
    rc = dfs_punch(s->dfs, s->file, offset, bytes);
    if (rc) {
        return rc;
    }

    /* Ensure durability */
    return dfs_sync(s->dfs);
}


/**
 * Block driver definition for DFS (Distributed File System).
 */
static BlockDriver bdrv_dfs = {
    .format_name = "dfs",
    .instance_size = sizeof(BDRVDFSState),
    .bdrv_parse_filename = qemu_dfs_parse_filename,
    .bdrv_file_open = qemu_dfs_open,
    .bdrv_close = qemu_dfs_close,
    .bdrv_co_create = qemu_dfs_co_create,
    .bdrv_co_create_opts = qemu_dfs_co_create_opts,
    .create_opts = &qemu_dfs_create_opts,
    .protocol_name = "dfs",

    .bdrv_co_preadv = qemu_dfs_co_preadv,
    .bdrv_co_pwritev = qemu_dfs_co_pwritev,
    .bdrv_co_flush_to_disk = qemu_dfs_co_flush,
    .bdrv_co_pdiscard = qemu_dfs_co_pdiscard,
    .bdrv_co_getlength = qemu_dfs_co_getlength,
    .bdrv_co_truncate = qemu_dfs_co_truncate,

    .strong_runtime_opts = qemu_dfs_runtime_opts,
};

static void bdrv_dfs_init(void)
{
    bdrv_register(&bdrv_dfs);
}

block_init(bdrv_dfs_init);