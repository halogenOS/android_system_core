/*
 * Copyright (C) 2019 The halogenOS Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include "fs_mgr.h"
#include "fs_mgr_priv.h"

namespace android {
namespace fs_mgr {

#define USERDATA_FBE_TEST_FILE "unencrypted/key/encrypted_key"
#define USERDATA_FDE_MAGIC "\xD0\xB5\xB1\xC4"
#define USERDATA_MEDIA_DIR "media"

bool IsFdeEncrypted(FstabEntry& entry) {
    FILE* partition = fopen(entry.blk_device.c_str(), "rb");
    if (!partition) {
        LERROR << "Could not open block device";
        return false;
    }
    int seek_pos = entry.length;
    if (!seek_pos) {
        // assume default
        seek_pos = -16384;
    }
    fseek(partition, seek_pos, SEEK_END);
    unsigned char magic[4];
    int read_len = fread(magic, 4, 1, partition);
    if (read_len != 1) {
        LERROR << "Unable to read magic";
        return false;
    }
    fclose(partition);
    return !memcmp(magic, USERDATA_FDE_MAGIC, 4);
}

bool IsFbeEncrypted(FstabEntry& entry) {
    int ret_mnt = mount(entry.blk_device.c_str(), "/data", entry.fs_type.c_str(),
                        MS_NOATIME | MS_NOEXEC | MS_NOSUID | MS_RDONLY, entry.fs_options.c_str());
    if (!ret_mnt) {
        struct stat statbuf;
        int printfbuf_size = sizeof("/data/") + sizeof(USERDATA_FBE_TEST_FILE) + 1;
        char printfbuf[printfbuf_size];
        bool is_fbe, umounted;
        int retry_count;

        // Using snprintf will make sure that there are no overflows
        // and that the string is always terminated with null, thus
        // memset is not needed anymore
        snprintf(printfbuf, printfbuf_size, "/data/%s", USERDATA_FBE_TEST_FILE);

        printfbuf[printfbuf_size - 1] = '\0';
        is_fbe = !stat(printfbuf, &statbuf);
        if (!is_fbe) {
            // Not FBE, check if /data/media exists

            // Reuse existing printfbuf (it's bigger than what we need)
            snprintf(printfbuf, printfbuf_size, "/data/%s", USERDATA_MEDIA_DIR);
            if (!stat(printfbuf, &statbuf)) {
                // Dir exists, data is decrypted
                is_fbe = false;
            } else {
                // Dir does not exist, check for decrypt file
                snprintf(printfbuf, printfbuf_size, "/data/decrypt");
                // This will be set to true if the file can't be found
                is_fbe = stat(printfbuf, &statbuf);
            }
        }

        umounted = false;
        retry_count = 5;
        while (retry_count-- > 0) {
            umounted = !umount("/data");
            if (retry_count) sleep(1);
        }
        if (!umounted) {
            LERROR << "Could not unmount temporarily mounted /data";
        }

        return is_fbe;
    } else {
        // Assume no mount = no fbe
        return false;
    }
}

void AutodetectEncryption(FstabEntry* entry) {
    if (IsFdeEncrypted(*entry)) {
        // full disk encryption
        entry->fs_mgr_flags.force_crypt = false;
        entry->fs_mgr_flags.crypt = true;
        entry->fs_mgr_flags.force_fde_or_fbe = false;
        entry->fs_mgr_flags.file_encryption = false;
        if (entry->key_loc.empty()) {
            // assume default
            entry->key_loc = "footer";
        }
        if (entry->length == 0) {
            // assume default
            entry->length = -16384;
        }
    } else if (IsFbeEncrypted(*entry)) {
        // file based encryption
        entry->fs_mgr_flags.force_crypt = false;
        entry->fs_mgr_flags.force_fde_or_fbe = false;
        entry->fs_mgr_flags.file_encryption = true;
        entry->length = 0;
        entry->key_loc.clear();
        if (entry->file_contents_mode.empty()) {
            // assume default
            entry->file_contents_mode = "ice";
        }
        if (entry->file_names_mode.empty()) {
            // assume default
            entry->file_names_mode = "aes-256-cts";
        }
    } else {
        entry->fs_mgr_flags.force_crypt = false;
        entry->fs_mgr_flags.crypt = false;
        entry->fs_mgr_flags.force_fde_or_fbe = false;
        entry->fs_mgr_flags.file_encryption = false;
        entry->length = 0;
        entry->key_loc.clear(); 
    }
}

}
}
