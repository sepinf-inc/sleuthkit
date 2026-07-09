/*
** The Sleuth Kit
**
** Copyright (c) 2021 Basis Technology Corp.  All rights reserved
** Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
**
** This software is distributed under the Common Public License 1.0
**
*/

#include "detect_encryption.h"

#include <stdlib.h>
#include <string.h>
#ifndef TSK_WIN32
#include <unistd.h>
#endif

// Scans the buffer and returns 1 if the given signature is found, 0 otherwise.
// Looks for the signature starting at each byte from startingOffset to endingOffset.
int
detectSignature(const char * signature, size_t signatureLen, size_t startingOffset, size_t endingOffset, const char * buf, size_t bufLen) {

    for (size_t offset = startingOffset; offset <= endingOffset; offset++) {
        if (offset + signatureLen > bufLen) {
            return 0;
        }

        if (memcmp(signature, buf + offset, signatureLen) == 0) {
            return 1;
        }
    }
    return 0;
}

// Returns 1 if LUKS signature is found, 0 otherwise
int
detectLUKS(const char * buf, size_t len) {
    const char * signature = "LUKS\xba\xbe";
    return detectSignature(signature, strlen(signature), 0, 0, buf, len);
}

// Returns 1 if BitLocker signature is found, 0 otherwise
int
detectBitLocker(const char * buf, size_t len) {

    // Look for the signature near the beginning of the buffer
    const char * signature = "-FVE-FS-";
    return detectSignature(signature, strlen(signature), 0, 16, buf, len);
}

// Returns 1 if FileVault signature is found, 0 otherwise
int
detectFileVault(const char * buf, size_t len) {
    const char * signature = "encrdsa";
    return detectSignature(signature, strlen(signature), 0, 0, buf, len);
}

// Returns 1 if Check Point signature is found, 0 otherwise
int
detectCheckPoint(const char * buf, size_t len) {
    // Look for the signature near the beginning of the buffer
    const char * signature = "Protect";
    return detectSignature(signature, strlen(signature), 80, 100, buf, len);
}

// Returns 1 if McAfee Safeboot signature is found, 0 otherwise
int
detectMcAfee(const char * buf, size_t len) {
    // Look for the signature near the beginning of the buffer. Check two capitalizations.
    const char * signature = "Safeboot";
    const char * altSignature = "SafeBoot";
    return (detectSignature(signature, strlen(signature), 0, 32, buf, len)
        | detectSignature(altSignature, strlen(altSignature), 0, 32, buf, len));
}

// Returns 1 if Guardian Edge signature is found, 0 otherwise
int
detectGuardianEdge(const char * buf, size_t len) {
    // Look for the signature near the beginning of the buffer
    const char * signature = "PCGM";
    return detectSignature(signature, strlen(signature), 0, 32, buf, len);
}

// Returns 1 if Sophos Safeguard signature is found, 0 otherwise
int
detectSophos(const char * buf, size_t len) {
    // Look for the signature near the beginning of the buffer
    const char * signature = "SGM400";
    const char * altSignature = "SGE400";
    return (detectSignature(signature, strlen(signature), 110, 150, buf, len)
        | detectSignature(altSignature, strlen(altSignature), 110, 150, buf, len));
}

// Returns 1 if WinMagic SecureDoc signature is found, 0 otherwise
int
detectWinMagic(const char * buf, size_t len) {
    // Look for the signature near the beginning of the buffer
    const char * signature = "WMSD";
    return detectSignature(signature, strlen(signature), 236, 256, buf, len);
}

// Returns 1 if Symantec PGP signature is found, 0 otherwise
int
detectSymantecPGP(const char * buf, size_t len) {
    // Look for the signature near the beginning of the buffer
    const char * signature = "\xeb\x48\x90PGPGUARD";
    return detectSignature(signature, strlen(signature), 0, 32, buf, len);
}

#define ENTROPY_BLOCK_LEN 65536
#define ENTROPY_MAX_BLOCKS 100

#ifndef TSK_WIN32
#include <pthread.h>

// State shared by the entropy worker threads. Blocks are assigned by
// stride (worker t handles blocks where block % numThreads == t); each
// worker fills an independent per-block histogram, and the main thread
// merges them in block order so the result is identical to the
// sequential pass, including the stop at the first failed read.
typedef struct {
    TSK_IMG_INFO *img_info;
    TSK_DADDR_T offset;
    uint64_t firstBlock;
    uint64_t endBlock;      // exclusive
    unsigned stride;
    unsigned lane;
    int (*blockCounts)[256];
    unsigned char *blockOk;
} entropy_worker_args;

static void *
entropyWorker(void *ptr) {
    entropy_worker_args *args = (entropy_worker_args *)ptr;
    char buf[ENTROPY_BLOCK_LEN];

    for (uint64_t i = args->firstBlock + args->lane; i < args->endBlock;
            i += args->stride) {
        if (tsk_img_read(args->img_info, args->offset + i * ENTROPY_BLOCK_LEN,
                buf, ENTROPY_BLOCK_LEN) != (ssize_t)ENTROPY_BLOCK_LEN) {
            continue;   // leave blockOk[i] unset; merge stops there
        }
        for (size_t j = 0; j < ENTROPY_BLOCK_LEN; j++) {
            unsigned char b = buf[j] & 0xff;
            args->blockCounts[i][b]++;
        }
        args->blockOk[i] = 1;
    }
    return NULL;
}
#endif

// Returns the entropy of the beginning of the image.
double
calculateEntropy(TSK_IMG_INFO * img_info, TSK_DADDR_T offset) {

    // Initialize frequency counts
    int byteCounts[256];
    for (int i = 0; i < 256; i++) {
        byteCounts[i] = 0;
    }

    // Read in blocks of 65536 bytes, skipping the first one that is more likely to contain header data.
    size_t bufLen = ENTROPY_BLOCK_LEN;
    size_t bytesRead = 0;

    // Number of full blocks available after the skipped header block
    uint64_t endBlock = 1;
    while (endBlock < ENTROPY_MAX_BLOCKS
        && (endBlock + 1) * bufLen <= (uint64_t)img_info->size - offset) {
        endBlock++;
    }

#ifndef TSK_WIN32
    // Read and count the blocks with a small pool of threads (the image
    // cache supports concurrent readers). Per-block histograms merged in
    // block order keep the result bit-identical to the sequential pass.
    // Disable with TSK_ENTROPY_THREADS=0.
    {
        const char *env = getenv("TSK_ENTROPY_THREADS");
        long nproc = sysconf(_SC_NPROCESSORS_ONLN);
        unsigned numThreads = (nproc > 4) ? 4 : (nproc > 1 ? (unsigned)nproc : 1);

        if ((env == NULL || strcmp(env, "0") != 0)
            && numThreads > 1 && endBlock - 1 >= 2 * numThreads) {

            int (*blockCounts)[256] = (int (*)[256])tsk_malloc(
                ENTROPY_MAX_BLOCKS * sizeof(*blockCounts));
            unsigned char *blockOk = (unsigned char *)tsk_malloc(ENTROPY_MAX_BLOCKS);
            pthread_t threads[4];
            entropy_worker_args args[4];
            unsigned started = 0;

            if (blockCounts != NULL && blockOk != NULL) {
                for (unsigned t = 0; t < numThreads; t++) {
                    args[t].img_info = img_info;
                    args[t].offset = offset;
                    args[t].firstBlock = 1;
                    args[t].endBlock = endBlock;
                    args[t].stride = numThreads;
                    args[t].lane = t;
                    args[t].blockCounts = blockCounts;
                    args[t].blockOk = blockOk;
                    if (pthread_create(&threads[t], NULL, entropyWorker,
                            &args[t]) != 0) {
                        break;
                    }
                    started++;
                }
                for (unsigned t = 0; t < started; t++) {
                    pthread_join(threads[t], NULL);
                }

                if (started == numThreads) {
                    // Merge in block order, stopping at the first failed
                    // read exactly like the sequential loop.
                    for (uint64_t i = 1; i < endBlock; i++) {
                        if (!blockOk[i]) {
                            break;
                        }
                        for (int b = 0; b < 256; b++) {
                            byteCounts[b] += blockCounts[i][b];
                        }
                        bytesRead += bufLen;
                    }
                    free(blockCounts);
                    free(blockOk);
                    goto compute;
                }
                // thread creation failed: fall through to sequential
                memset(byteCounts, 0, sizeof(byteCounts));
                bytesRead = 0;
            }
            free(blockCounts);
            free(blockOk);
        }
    }
#endif

    {
        char* buf = (char*)tsk_malloc(bufLen);
        if (buf == NULL) {
            return 0.0;
        }
        for (uint64_t i = 1; i < endBlock; i++) {
            if (tsk_img_read(img_info, offset + i * bufLen, buf, bufLen) != (ssize_t) bufLen) {
                break;
            }

            for (size_t j = 0; j < bufLen; j++) {
                unsigned char b = buf[j] & 0xff;
                byteCounts[b]++;
            }
            bytesRead += bufLen;
        }
        free(buf);
    }

#ifndef TSK_WIN32
  compute:
#endif
    // Calculate entropy
    {
        double entropy = 0.0;
        double log2 = log(2);
        for (int i = 0; i < 256; i++) {
            if (byteCounts[i] > 0) {
                double p = (double)(byteCounts[i]) / bytesRead;
                entropy -= p * log(p) / log2;
            }
        }
        return entropy;
    }
}

/**
 * Detect volume-type encryption in the image starting at the given offset.
 * May return null on error. Note that client is responsible for freeing the result.
 * 
 * @param img_info The open image
 * @param offset   The offset for the beginning of the volume
 *
 * @return encryption_detected_result containing the result of the check. null for certain types of errors.
*/
encryption_detected_result*
detectVolumeEncryption(TSK_IMG_INFO * img_info, TSK_DADDR_T offset) {

    encryption_detected_result* result = (encryption_detected_result*)tsk_malloc(sizeof(encryption_detected_result));
    if (result == NULL) {
        return result;
    }
    result->encryptionType = ENCRYPTION_DETECTED_NONE;
    result->desc[0] = '\0';

    if (img_info == NULL) {
        return result;
    }
    if (offset > (uint64_t)img_info->size) {
        return result;
    }

    // Read the beginning of the image. There should be room for all the signature searches.
    size_t len = 1024;
    char* buf = (char*)tsk_malloc(len);
    if (buf == NULL) {
        return result;
    }
    if (tsk_img_read(img_info, offset, buf, len) != (ssize_t)len) {
        free(buf);
        return result;
    }

    // Look for BitLocker signature
    if (detectBitLocker(buf, len)) {
        result->encryptionType = ENCRYPTION_DETECTED_SIGNATURE;
        snprintf(result->desc, TSK_ERROR_STRING_MAX_LENGTH, "BitLocker");
        free(buf);
        return result;
    }

    // Look for Linux Unified Key Setup (LUKS) signature
    if (detectLUKS(buf, len)) {
        result->encryptionType = ENCRYPTION_DETECTED_SIGNATURE;
        snprintf(result->desc, TSK_ERROR_STRING_MAX_LENGTH, "LUKS");
        free(buf);
        return result;
    }

    // Look for FileVault
    if (detectFileVault(buf, len)) {
        result->encryptionType = ENCRYPTION_DETECTED_SIGNATURE;
        snprintf(result->desc, TSK_ERROR_STRING_MAX_LENGTH, "FileVault");
        free(buf);
        return result;
    }

    free(buf);

    // Final test - check entropy
    double entropy = calculateEntropy(img_info, offset);
    if (entropy > 7.5) {
        result->encryptionType = ENCRYPTION_DETECTED_ENTROPY;
        snprintf(result->desc, TSK_ERROR_STRING_MAX_LENGTH, "High entropy (%1.2lf)", entropy);
        return result;
    }

    return result;
}

/**
* Detect full disk encryption in the image starting at the given offset.
* May return null on error. Note that client is responsible for freeing the result.
*
* @param img_info The open image
* @param offset   The offset for the beginning of the image TODO TODO do we need this??
*
* @return encryption_detected_result containing the result of the check. null for certain types of errors.
*/
encryption_detected_result*
detectDiskEncryption(TSK_IMG_INFO * img_info, TSK_DADDR_T offset) {

    encryption_detected_result* result = (encryption_detected_result*)tsk_malloc(sizeof(encryption_detected_result));
    if (result == NULL) {
        return result;
    }
    result->encryptionType = ENCRYPTION_DETECTED_NONE;
    result->desc[0] = '\0';

    if (img_info == NULL) {
        return result;
    }
    if (offset > (uint64_t)img_info->size) {
        return result;
    }

    // Read the beginning of the image. There should be room for all the signature searches.
    size_t len = 1024;
    char* buf = (char*)tsk_malloc(len);
    if (buf == NULL) {
        return result;
    }
    if (tsk_img_read(img_info, offset, buf, len) != (ssize_t)len) {
        free(buf);
        return result;
    }

    // Look for Symatec PGP signature
    if (detectSymantecPGP(buf, len)) {
        result->encryptionType = ENCRYPTION_DETECTED_SIGNATURE;
        snprintf(result->desc, TSK_ERROR_STRING_MAX_LENGTH, "Symantec PGP");
        free(buf);
        return result;
    }

    // Look for McAfee Safeboot signature
    if (detectMcAfee(buf, len)) {
        result->encryptionType = ENCRYPTION_DETECTED_SIGNATURE;
        snprintf(result->desc, TSK_ERROR_STRING_MAX_LENGTH, "McAfee Safeboot");
        free(buf);
        return result;
    }

    // Look for Sophos Safeguard
    if (detectSophos(buf, len)) {
        result->encryptionType = ENCRYPTION_DETECTED_SIGNATURE;
        snprintf(result->desc, TSK_ERROR_STRING_MAX_LENGTH, "Sophos Safeguard");
        free(buf);
        return result;
    }

    // Look for Guardian Edge signature
    if (detectGuardianEdge(buf, len)) {
        result->encryptionType = ENCRYPTION_DETECTED_SIGNATURE;
        snprintf(result->desc, TSK_ERROR_STRING_MAX_LENGTH, "Guardian Edge");
        free(buf);
        return result;
    }

    // Look for Check Point signature
    if (detectCheckPoint(buf, len)) {
        result->encryptionType = ENCRYPTION_DETECTED_SIGNATURE;
        snprintf(result->desc, TSK_ERROR_STRING_MAX_LENGTH, "Check Point");
        free(buf);
        return result;
    }

    // Look for WinMagic SecureDoc signature
    if (detectWinMagic(buf, len)) {
        result->encryptionType = ENCRYPTION_DETECTED_SIGNATURE;
        snprintf(result->desc, TSK_ERROR_STRING_MAX_LENGTH, "WinMagic SecureDoc");
        free(buf);
        return result;
    }
    free(buf);
    return result;
}


