// SPDX-License-Identifier: GPL-2.0-only

#include <linux/ktime.h>
#include <linux/highmem.h>
#include <linux/sched/clock.h>
#include <linux/zstd.h>
#include <linux/lz4.h>
#include <linux/string.h>
#include "nvmev.h"
#include "kv_ftl.h"
#include "logTable.h"

#define WRITE_DELAY_SLC 15195
#define WRITE_DELAY_MLC 43195
#define WRITE_DELAY_QLC 99195
#define WRITE_LATENCY 2934
#define READ_DELAY_SLC 63922
#define READ_DELAY_MLC 145922
#define READ_DELAY_QLC 299922
#define READ_LATENCY 1467

typedef enum _cell_mode_t { MAX, SLC, MLC, QLC } cell_mode_t;

static inline int get_byte_entropy(const unsigned char *pData, size_t total_size)
{
	unsigned short int nCountTable[256] = {
		0,
	};
	unsigned int entropy = 0;
	unsigned short int i;
	size_t total_size2;

	total_size2 = 1024;

	for (i = 0; i < total_size; i += 4)
		nCountTable[pData[i]]++;

	for (i = 0; i < 256; i++)
		if (nCountTable[i]) {
			entropy += nCountTable[i] *
				   (ilog2_1000(total_size2) - ilog2_1000(nCountTable[i]));
		}

	return entropy;
}

void print_big(char *data, size_t length)
{
	int i = 0;
	int j = 0;
	int k = length / 512;
	int left = length % 512;
	char *temp = data;
	char chunk[512] = { 0 };
	printk("[%s]: size: %ld left: %d\n", __func__, length, left);
	for (i = 0; i < k; i++) {
		printk("[%d]\n", (i + 1));
		memset(chunk, 0, 512);
		memcpy(chunk, temp, 512);
		// snprintf(chunk, 513, "%s", temp);
		// printk("%s\n", chunk);
		// if (!i) {
		// 	for (j = 0; j < 512; j++)
		// 		printk(KERN_CONT "%d ", *(temp + j));
		// } else {
		// 	for (j = 0; j < 512; j++)
		// 		printk(KERN_CONT "%c", *(temp + j));
		// }
		for (j = 0; j < 512; j++)
			printk(KERN_CONT "%c", *(temp + j));

		temp += 512;
	}
	if (left) {
		memset(chunk, 0, 512);
		printk("[left]\n");
		memcpy(chunk, temp, left);
		for (j = 0; j < left; j++)
			printk(KERN_CONT "%c", *(temp + j));
		// snprintf(chunk, left + 1, "%s", temp);
		// printk("%s\n", chunk);
	}
}
static const struct allocator_ops append_only_ops = {
	.init = append_only_allocator_init,
	.allocate = append_only_allocate,
	.kill = append_only_kill,
};

static const struct allocator_ops bitmap_ops = {
	.init = bitmap_allocator_init,
	.allocate = bitmap_allocate,
	.kill = bitmap_kill,
};

static inline unsigned long long __get_wallclock(void)
{
	return cpu_clock(nvmev_vdev->config.cpu_nr_dispatcher);
}

static size_t __cmd_io_size(struct nvme_rw_command *cmd)
{
	NVMEV_DEBUG("%d lba %llu length %d, %llx %llx\n", cmd->opcode, cmd->slba, cmd->length,
		    cmd->prp1, cmd->prp2);

	return (cmd->length + 1) << 9;
}

static unsigned int cmd_key_length(struct nvme_kv_command cmd)
{
	if (cmd.common.opcode == nvme_cmd_kv_store) {
		return cmd.kv_store.key_len + 1;
	} else if (cmd.common.opcode == nvme_cmd_kv_retrieve) {
		return cmd.kv_retrieve.key_len + 1;
	} else if (cmd.common.opcode == nvme_cmd_kv_delete) {
		return cmd.kv_delete.key_len + 1;
	} else {
		return cmd.kv_store.key_len + 1;
	}
}

static unsigned int cmd_value_length(struct nvme_kv_command cmd)
{
	if (cmd.common.opcode == nvme_cmd_kv_store) {
		return cmd.kv_store.value_len << 2;
	} else if (cmd.common.opcode == nvme_cmd_kv_retrieve) {
		return cmd.kv_retrieve.value_len << 2;
	} else {
		return cmd.kv_store.value_len << 2;
	}
}

static unsigned int cmd_value_compressed_length(struct nvme_kv_command cmd)
{
	if (!cmd.kv_store.rsvd2 || !cmd.kv_retrieve.rsvd2) {
		return cmd_value_length(cmd);
	}
	if (cmd.common.opcode == nvme_cmd_kv_store) {
		return cmd.kv_store.rsvd2;
	} else if (cmd.common.opcode == nvme_cmd_kv_retrieve) {
		return cmd.kv_retrieve.rsvd2;
	} else {
		return cmd.kv_store.rsvd2;
	}
}

/* Return the time to complete */
static unsigned long long __schedule_io_units(int opcode, unsigned long lba, unsigned int length,
					      unsigned long long nsecs_start, cell_mode_t cell_mode)
{
	unsigned int io_unit_size = 1 << nvmev_vdev->config.io_unit_shift;
	unsigned int io_unit =
		(lba >> (nvmev_vdev->config.io_unit_shift - 9)) % nvmev_vdev->config.nr_io_units;
	int nr_io_units = min(nvmev_vdev->config.nr_io_units, DIV_ROUND_UP(length, io_unit_size));

	unsigned long long latest; /* Time of completion */
	unsigned int delay = 0;
	unsigned int latency = 0;
	unsigned int trailing = 0;
	if (opcode == nvme_cmd_write || opcode == nvme_cmd_kv_store ||
	    opcode == nvme_cmd_kv_batch) {
#ifdef COMPRESSION
		trailing = nvmev_vdev->config.write_trailing;
		switch (cell_mode) {
		case SLC:
			delay = WRITE_DELAY_SLC;
			latency = WRITE_LATENCY;
			break;
		case MLC:
			delay = WRITE_DELAY_MLC;
			latency = WRITE_LATENCY;
			break;
		case QLC:
			delay = WRITE_DELAY_QLC;
			latency = WRITE_LATENCY;
			break;
		default:
			delay = nvmev_vdev->config.write_delay;
			latency = nvmev_vdev->config.write_time;
		}
		//NOTE - debug
		COMP_DEBUG("delay:%u latency:%u trailing:%u\n", delay, latency, trailing);
#else
		// delay = nvmev_vdev->config.write_delay;
		// latency = nvmev_vdev->config.write_time;
		delay = WRITE_DELAY_MLC;
		latency = WRITE_LATENCY;
		trailing = nvmev_vdev->config.write_trailing;
		COMP_DEBUG("delay:%u latency:%u trailing:%u\n", delay, latency, trailing);
#endif
	} else if (opcode == nvme_cmd_read || opcode == nvme_cmd_kv_retrieve) {
#ifdef COMPRESSION
		trailing = nvmev_vdev->config.read_trailing;
		switch (cell_mode) {
		case SLC:
			delay = READ_DELAY_SLC;
			latency = READ_LATENCY;
			break;
		case MLC:
			delay = READ_DELAY_MLC;
			latency = READ_LATENCY;
			break;
		case QLC:
			delay = READ_DELAY_QLC;
			latency = READ_LATENCY;
			break;
		default:
			delay = nvmev_vdev->config.read_delay;
			latency = nvmev_vdev->config.read_time;
		}
#else
		// delay = nvmev_vdev->config.read_delay;
		// latency = nvmev_vdev->config.read_time;
		delay = READ_DELAY_MLC;
		latency = READ_LATENCY;
		trailing = nvmev_vdev->config.read_trailing;

#endif
	}

	latest = max(nsecs_start, nvmev_vdev->io_unit_stat[io_unit]) + delay;

	do {
		latest += latency;
		nvmev_vdev->io_unit_stat[io_unit] = latest;

		if (nr_io_units-- > 0) {
			nvmev_vdev->io_unit_stat[io_unit] += trailing;
		}

		length -= min(length, io_unit_size);
		if (++io_unit >= nvmev_vdev->config.nr_io_units)
			io_unit = 0;
	} while (length > 0);

	//COMP_DEBUG("Estimated Time(2): %llu\n", latest);
	return latest;
}

static unsigned long long __schedule_flush(struct nvmev_request *req)
{
	unsigned long long latest = 0;
	int i;

	for (i = 0; i < nvmev_vdev->config.nr_io_units; i++) {
		latest = max(latest, nvmev_vdev->io_unit_stat[i]);
	}

	return latest;
}

/* KV-SSD Mapping Management */

static size_t allocate_mem_offset(struct kv_ftl *kv_ftl, struct nvme_kv_command cmd)
{
	if (cmd.common.opcode == nvme_cmd_kv_store) {
		u64 length_bytes = cmd_value_length(cmd);
		size_t offset;

		offset = kv_ftl->allocator_ops.allocate(length_bytes, NULL);

		if (offset == -1) {
			NVMEV_ERROR("mem alloc failed");
			return 0;
		} else {
			NVMEV_DEBUG("allocate memory offset %lu for %u %u\n", offset,
				    cmd_key_length(cmd), cmd_value_length(cmd));
			return offset;
		}
	} else {
		NVMEV_ERROR("Couldn't allocate mem offset %d", cmd.common.opcode);
		return 0;
	}
}

static size_t allocate_mem_offset_by_length(struct kv_ftl *kv_ftl, int val_len)
{
	u64 length_bytes = val_len;
	size_t offset;

	offset = kv_ftl->allocator_ops.allocate(length_bytes, NULL);

	if (offset == -1) {
		NVMEV_ERROR("mem alloc failed");
		return 0;
	} else {
		NVMEV_DEBUG("allocate memory offset %lu for %u\n", offset, val_len);
		return offset;
	}
}

static unsigned int get_hash_slot(struct kv_ftl *kv_ftl, char *key, u32 key_len)
{
	return hash_function(key, key_len) % kv_ftl->hash_slots;
}

static void chain_mapping(struct kv_ftl *kv_ftl, unsigned int prev, unsigned int slot)
{
	kv_ftl->kv_mapping_table[prev].next_slot = slot;
}

static unsigned int find_next_slot(struct kv_ftl *kv_ftl, int original_slot, int *prev_slot)
{
	unsigned int ret_slot = original_slot;

	while (kv_ftl->kv_mapping_table[ret_slot].mem_offset != -1) {
		ret_slot++;
		if (ret_slot >= kv_ftl->hash_slots)
			ret_slot = 0;
	}

	*prev_slot = original_slot;

	if (prev_slot < 0) {
		NVMEV_ERROR("Prev slot less than 0\n");
	}

	NVMEV_DEBUG("Collision at slot %d, found new slot %u\n", original_slot, ret_slot);
	if (ret_slot - original_slot > 3)
		NVMEV_DEBUG("Slot difference: %d\n", ret_slot - original_slot);

	return ret_slot;
}

static unsigned int new_mapping_entry(struct kv_ftl *kv_ftl, struct nvme_kv_command cmd,
				      size_t val_offset, size_t compressed_size)
{
	unsigned int slot = -1;
	unsigned int prev_slot;
	BUG_ON(val_offset < 0 || val_offset >= nvmev_vdev->config.storage_size);

	slot = get_hash_slot(kv_ftl, cmd.kv_store.key, cmd_key_length(cmd));

	prev_slot = -1;
	if (kv_ftl->kv_mapping_table[slot].mem_offset != -1) {
		NVMEV_DEBUG("Collision\n");
		slot = find_next_slot(kv_ftl, slot, &prev_slot);
	}

	if (slot < 0 || slot >= kv_ftl->hash_slots) {
		NVMEV_ERROR("slot < 0 || slot >= kv_ftl->hash_slots\n");
	}

	memcpy(kv_ftl->kv_mapping_table[slot].key, cmd.kv_store.key, cmd.kv_store.key_len + 1);
	kv_ftl->kv_mapping_table[slot].mem_offset = val_offset;
	kv_ftl->kv_mapping_table[slot].length = cmd_value_length(cmd);
#ifdef COMPRESSION
	kv_ftl->kv_mapping_table[slot].compressed_size = compressed_size;
	if (compressed_size) {
		// COMP_DEBUG("COMPRESSED: TRUE\n");
		kv_ftl->kv_mapping_table[slot].compressed = true;
	} else {
		// COMP_DEBUG("COMPRESSED: FALSE\n");
		kv_ftl->kv_mapping_table[slot].compressed = false;
	}
#endif
	/* hash chaining */
	if (prev_slot != -1) {
		NVMEV_DEBUG("Linking slot %d to new slot %d", prev_slot, slot);
		chain_mapping(kv_ftl, prev_slot, slot);
	}

	NVMEV_DEBUG("New mapping entry key %s offset %lu length %u compressed_size %lu slot %u\n",
		    cmd.kv_store.key, val_offset, cmd_value_length(cmd), compressed_size, slot);

	return 0;
}

static unsigned int new_mapping_entry_by_key(struct kv_ftl *kv_ftl, unsigned char *key, int key_len,
					     int val_len, size_t val_offset)
{
	unsigned int slot = -1;
	unsigned int prev_slot;
	BUG_ON(val_offset < 0 || val_offset >= nvmev_vdev->config.storage_size);

	slot = get_hash_slot(kv_ftl, key, key_len);

	prev_slot = -1;
	if (kv_ftl->kv_mapping_table[slot].mem_offset != -1) {
		NVMEV_DEBUG("Collision\n");
		slot = find_next_slot(kv_ftl, slot, &prev_slot);
	}

	if (slot < 0 || slot >= kv_ftl->hash_slots) {
		NVMEV_ERROR("slot < 0 || slot >= kv_ftl->hash_slots\n");
	}

	memcpy(kv_ftl->kv_mapping_table[slot].key, key, key_len);
	kv_ftl->kv_mapping_table[slot].mem_offset = val_offset;
	kv_ftl->kv_mapping_table[slot].length = val_len;
	/* hash chaining */
	if (prev_slot != -1) {
		NVMEV_DEBUG("Linking slot %d to new slot %d", prev_slot, slot);
		chain_mapping(kv_ftl, prev_slot, slot);
	}

	NVMEV_DEBUG("New mapping entry key %s offset %lu length %u slot %u\n", key, val_offset,
		    val_len, slot);

	return 0;
}

static unsigned int update_mapping_entry(struct kv_ftl *kv_ftl, struct nvme_kv_command cmd)
{
	unsigned int slot = 0;
	bool found = false;
	// u64 t0, t1;

	u32 count = 0;

	// t0 = ktime_get_ns();
	slot = get_hash_slot(kv_ftl, cmd.kv_store.key, cmd_key_length(cmd));
	// t1 = ktime_get_ns();
	// printk("Hashing took %llu\n", t1-t0);

	while (kv_ftl->kv_mapping_table[slot].mem_offset != -1) {
		NVMEV_DEBUG("Comparing %s | %.*s\n", cmd.kv_store.key, cmd_key_length(cmd),
			    kv_ftl->kv_mapping_table[slot].key);
		count++;

		if (count > 10) {
			NVMEV_ERROR("Searched %u times", count);
			// break;
		}

		if (memcmp(cmd.kv_store.key, kv_ftl->kv_mapping_table[slot].key,
			   cmd_key_length(cmd)) == 0) {
			NVMEV_DEBUG("1 Found\n");
			found = true;
			break;
		}

		slot = kv_ftl->kv_mapping_table[slot].next_slot;
		if (slot == -1)
			break;
		// t1 = ktime_get_ns();
		// printk("Comparison took %llu", t1-t0);
	}

	if (found) {
		NVMEV_DEBUG("Updating mapping length %lu to %u for key %s\n",
			    kv_ftl->kv_mapping_table[slot].length, cmd_value_length(cmd),
			    cmd.kv_store.key);
		kv_ftl->kv_mapping_table[slot].length = cmd_value_length(cmd);
	}

	if (!found) {
		NVMEV_ERROR("No mapping found for key %s\n", cmd.kv_store.key);
		return 1;
	}

	return 0;
}

static struct mapping_entry get_mapping_entry(struct kv_ftl *kv_ftl, struct nvme_kv_command cmd)
{
	struct mapping_entry mapping;
	// char *key = NULL;
	unsigned int slot = 0;
	bool found = false;
	// u64 t0, t1;

	u32 count = 0;

	memset(&mapping, -1, sizeof(struct mapping_entry)); // init mapping
	mapping.compressed = false;

	// t0 = ktime_get_ns();
	slot = get_hash_slot(kv_ftl, cmd.kv_store.key, cmd_key_length(cmd));
	// t1 = ktime_get_ns();
	// printk("Hashing took %llu\n", t1-t0);

	while (kv_ftl->kv_mapping_table[slot].mem_offset != -1) {
		NVMEV_DEBUG("Comparing %s | %.*s\n", cmd.kv_store.key, cmd_key_length(cmd),
			    kv_ftl->kv_mapping_table[slot].key);
		count++;

		if (count > 10) {
			NVMEV_DEBUG("Searched %u times", count);
			// break;
		}

		if (memcmp(cmd.kv_store.key, kv_ftl->kv_mapping_table[slot].key,
			   cmd_key_length(cmd)) == 0) {
			NVMEV_DEBUG("1 Found\n");
			found = true;
			break;
		}

		slot = kv_ftl->kv_mapping_table[slot].next_slot;
		if (slot == -1)
			break;
		NVMEV_DEBUG("Next slot %d", slot);
		// t1 = ktime_get_ns();
		// printk("Comparison took %llu", t1-t0);
	}

	if (found) {
		NVMEV_DEBUG("2 Found\n");
		memcpy(mapping.key, kv_ftl->kv_mapping_table[slot].key, cmd_key_length(cmd));
		mapping.mem_offset = kv_ftl->kv_mapping_table[slot].mem_offset;
		mapping.next_slot = kv_ftl->kv_mapping_table[slot].next_slot;
		mapping.length = kv_ftl->kv_mapping_table[slot].length;
		mapping.compressed = kv_ftl->kv_mapping_table[slot].compressed;
		mapping.compressed_size = kv_ftl->kv_mapping_table[slot].compressed_size;
	}

	if (!found)
		NVMEV_DEBUG("No mapping found for key %s\n", cmd.kv_store.key);
	else
		NVMEV_DEBUG("Returning mapping %lu length %lu for key %s\n", mapping.mem_offset,
			    mapping.length, cmd.kv_store.key);

	return mapping;
}

static struct mapping_entry get_mapping_entry_by_key(struct kv_ftl *kv_ftl, unsigned char *key,
						     int key_len)
{
	struct mapping_entry mapping;
	// char *key = NULL;
	unsigned int slot = 0;
	bool found = false;
	// u64 t0, t1;

	u32 count = 0;

	memset(&mapping, -1, sizeof(struct mapping_entry)); // init mapping

	// t0 = ktime_get_ns();
	slot = get_hash_slot(kv_ftl, key, key_len);
	// t1 = ktime_get_ns();
	// printk("Hashing took %llu\n", t1-t0);

	while (kv_ftl->kv_mapping_table[slot].mem_offset != -1) {
		NVMEV_DEBUG("Comparing %s | %.*s\n", key, key_len,
			    kv_ftl->kv_mapping_table[slot].key);
		count++;

		if (count > 10) {
			NVMEV_DEBUG("Searched %u times", count);
			// break;
		}

		if (memcmp(key, kv_ftl->kv_mapping_table[slot].key, key_len) == 0) {
			NVMEV_DEBUG("1 Found\n");
			found = true;
			break;
		}

		slot = kv_ftl->kv_mapping_table[slot].next_slot;
		if (slot == -1)
			break;
		NVMEV_DEBUG("Next slot %d", slot);
		// t1 = ktime_get_ns();
		// printk("Comparison took %llu", t1-t0);
	}

	if (found) {
		NVMEV_DEBUG("2 Found\n");
		memcpy(mapping.key, kv_ftl->kv_mapping_table[slot].key, key_len);
		mapping.mem_offset = kv_ftl->kv_mapping_table[slot].mem_offset;
		mapping.next_slot = kv_ftl->kv_mapping_table[slot].next_slot;
		mapping.length = kv_ftl->kv_mapping_table[slot].length;
	}

	if (!found)
		NVMEV_DEBUG("No mapping found for key %s\n", key);
	else
		NVMEV_DEBUG("Returning mapping %lu length %lu for key %s\n", mapping.mem_offset,
			    mapping.length, key);

	return mapping;
}

static struct mapping_entry delete_mapping_entry(struct kv_ftl *kv_ftl, struct nvme_kv_command cmd)
{
	struct mapping_entry mapping;
	// char *key = NULL;
	unsigned int slot = 0;
	bool found = false;
	// u64 t0, t1;

	u32 count = 0;

	memset(&mapping, -1, sizeof(struct mapping_entry)); // init mapping

	// t0 = ktime_get_ns();
	slot = get_hash_slot(kv_ftl, cmd.kv_store.key, cmd_key_length(cmd));
	// t1 = ktime_get_ns();
	// printk("Hashing took %llu\n", t1-t0);

	while (kv_ftl->kv_mapping_table[slot].mem_offset != -1) {
		NVMEV_DEBUG("Comparing %s | %.*s\n", cmd.kv_store.key, cmd_key_length(cmd),
			    kv_ftl->kv_mapping_table[slot].key);
		count++;

		if (count > 10) {
			NVMEV_DEBUG("Searched %u times", count);
			// break;
		}

		if (memcmp(cmd.kv_store.key, kv_ftl->kv_mapping_table[slot].key,
			   cmd_key_length(cmd)) == 0) {
			NVMEV_DEBUG("1 Found\n");
			found = true;
			break;
		}

		slot = kv_ftl->kv_mapping_table[slot].next_slot;
		if (slot == -1)
			break;
		NVMEV_DEBUG("Next slot %d", slot);
		// t1 = ktime_get_ns();
		// printk("Comparison took %llu", t1-t0);
	}

	if (found) {
		NVMEV_DEBUG("2 Found\n");
		memset(&(kv_ftl->kv_mapping_table[slot]), -1, sizeof(struct mapping_entry));
	}

	if (!found)
		NVMEV_DEBUG("No mapping found for key %s\n", cmd.kv_store.key);
	else
		NVMEV_DEBUG("Deleting mapping %lu length %lu for key %s\n", mapping.mem_offset,
			    mapping.length, cmd.kv_store.key);

	return mapping;
}

/* KV-SSD IO */

/*
 * 1. find mapping_entry
 * if kv_store
 *   if mapping_entry exist -> write to mem_offset
 *   else -> allocate mem_offset and write
 * else if kv_retrieve
 *   if mapping_entry exist -> read from mem_offset
 *   else -> key doesn't exist!
 */
#ifdef COMPRESSION
unsigned int try_to_compress(struct nvme_kv_command cmd)
{
	void *workmem, *vaddr;
	char *compressed_data;
	int prp_offs = 0;
	int prp2_offs = 0;
	int i = 0;
	int flag = 0;
	u64 paddr;
	u64 *paddr_list = NULL;
	size_t length, remaining;
	size_t compressed_size = 0;
	size_t mem_offs = 0;
	size_t offset = 0;
	char *data;
	int output_size;
	unsigned int expected_comprate;

	length = cmd_value_length(cmd);

	// data = kzalloc(length, GFP_KERNEL);
	data = (char *)vzalloc(length);
	// COMP_DEBUG("data: %p\n", data);
	if (!data) {
		COMP_DEBUG("vzalloc error data(2)\n");
	}
	// COMP_DEBUG("-----LOADING DATA-----\n");

	remaining = length;
	while (remaining) {
		size_t io_size;
		mem_offs = 0;
		prp_offs++;
		if (prp_offs == 1) {
			paddr = kv_io_cmd_value_prp(cmd, 1);
		} else if (prp_offs == 2) {
			paddr = kv_io_cmd_value_prp(cmd, 2);
			if (remaining > PAGE_SIZE) {
				paddr_list = kmap_atomic_pfn(PRP_PFN(paddr)) +
					     (paddr & PAGE_OFFSET_MASK);
				paddr = paddr_list[prp2_offs++];
			}
		} else {
			paddr = paddr_list[prp2_offs++];
		}

		vaddr = kmap_atomic_pfn(PRP_PFN(paddr));

		io_size = min_t(size_t, remaining, PAGE_SIZE);

		if (paddr & PAGE_OFFSET_MASK) { // 일반 block io면 언제 여기에 해당?
			mem_offs = paddr & PAGE_OFFSET_MASK;
			if (io_size + mem_offs > PAGE_SIZE)
				io_size = PAGE_SIZE - mem_offs;
		}
		// COMP_DEBUG("offset: %ld, io_size: %ld\n", offset, io_size);
		// COMP_DEBUG("vaddr: %p, mem_offs: %ld\n", vaddr, mem_offs);
		memcpy(data + offset, vaddr + mem_offs, io_size);
		remaining -= io_size;
		offset += io_size;
	}
	// COMP_DEBUG("-----LOADING DONE-----\n");
	// COMP_DEBUG("KEY: %s\n", cmd.kv_store.key);
	// COMP_DEBUG("Loaded data below: \n");
	/* calculate whether to compress or not */
	expected_comprate = ((get_byte_entropy(data, length) / 1024) * 10000) / 8000;
	if (expected_comprate < 5000) {
		flag = 1;
	}
	// COMP_DEBUG("-----COMPRESSING-----\n");
	// COMP_DEBUG("[%s]: comprate: %u\n", __func__, expected_comprate);
	if (flag) {
		COMP_DEBUG("------- COMPRESSION GOOD -------\n");
		workmem = vmalloc(LZ4_MEM_COMPRESS);
		if (!workmem) {
			COMP_DEBUG("vzalloc error workmem(2)\n");
		}

		output_size = LZ4_COMPRESSBOUND(length);
		// COMP_DEBUG("output size: %d\n", output_size);
		compressed_data = (char *)vzalloc(output_size);
		// COMP_DEBUG("compressed_data: %p\n", compressed_data);
		if (!compressed_data) {
			COMP_DEBUG("vzalloc error compressed_data(2)\n");
		}

		compressed_size = LZ4_compress_default(data, compressed_data, (int)length,
						       output_size, workmem);
		// COMP_DEBUG("data(3): %p\n", data);
		// COMP_DEBUG("compressed_data(2): %p\n", compressed_data);
		// COMP_DEBUG("compressed size: %ld compressed data:\n", compressed_size);
		// print_big(compressed_data, compressed_size);

		// COMP_DEBUG("-----COMPRESSING DONE-----\n");
		if (compressed_size) {
			// COMP_DEBUG("-----COPYING DATA-----\n");
			remaining = compressed_size;
			prp_offs = 0;
			offset = 0;
			while (remaining) {
				size_t io_size;
				mem_offs = 0;
				prp_offs++;
				if (prp_offs == 1) {
					paddr = kv_io_cmd_value_prp(cmd, 1);
				} else if (prp_offs == 2) {
					paddr = kv_io_cmd_value_prp(cmd, 2);
					if (remaining > PAGE_SIZE) {
						paddr_list = kmap_atomic_pfn(PRP_PFN(paddr)) +
							     (paddr & PAGE_OFFSET_MASK);
						paddr = paddr_list[prp2_offs++];
					}
				} else {
					paddr = paddr_list[prp2_offs++];
				}

				vaddr = kmap_atomic_pfn(PRP_PFN(paddr));

				io_size = min_t(size_t, remaining, PAGE_SIZE);

				if (paddr & PAGE_OFFSET_MASK) { // 일반 block io면 언제 여기에 해당?
					mem_offs = paddr & PAGE_OFFSET_MASK;
					if (io_size + mem_offs > PAGE_SIZE)
						io_size = PAGE_SIZE - mem_offs;
				}
				// COMP_DEBUG("offset: %ld, io_size: %ld\n", offset, io_size);
				// COMP_DEBUG("vaddr: %p, mem_offs: %ld\n", vaddr, mem_offs);
				memcpy(vaddr + mem_offs, compressed_data + offset, io_size);
				remaining -= io_size;
				offset += io_size;
			}
			// COMP_DEBUG("-----COPYING DONE-----\n");
		} else {
			COMP_DEBUG("COMPRESSION FAIL\n");
		}
		vfree(workmem);
		vfree(data);
		vfree(compressed_data);
		workmem = NULL;
		data = NULL;
		compressed_data = NULL;
	} else {
		COMP_DEBUG("----- DO NOT COMPRESS THIS DATA! size: %ld -----\n", compressed_size);
	}
	return (compressed_size ? compressed_size : 0);
}

int decompress(struct nvme_kv_command cmd, struct kv_ftl *kv_ftl)
{
	void *vaddr;
	char *decompressed;
	int prp_offs = 0;
	int prp2_offs = 0;
	int i = 0;
	u64 paddr;
	u64 *paddr_list = NULL;
	size_t length, remaining, original_size;
	size_t mem_offs = 0;
	size_t offset = 0;
	char *data;
	struct mapping_entry entry;
	int status = 0;

	entry = get_mapping_entry(kv_ftl, cmd);
	offset = entry.mem_offset;
	length = entry.compressed_size;
	original_size = cmd_value_length(cmd);

	data = (char *)vzalloc(length);
	if (!data) {
		COMP_DEBUG("vmalloc error data\n");
	}
	// COMP_DEBUG("-----GETTING COMPRESSED DATA-----\n");
	memcpy(data, nvmev_vdev->storage_mapped + offset, length);
	// COMP_DEBUG("-----GETTING DONE-----\n");
	COMP_DEBUG("KEY: %s\n", cmd.kv_store.key);
	// COMP_DEBUG("Loaded data below: \n");
	// print_big(data, length);
	// COMP_DEBUG("-----DECOMPRESSING-----\n");
	decompressed = (char *)vzalloc(original_size);
	if (!decompressed) {
		COMP_DEBUG("vmalloc error compressed_data\n");
	}
	if ((status = LZ4_decompress_fast(data, decompressed, original_size)) < 0) {
		return status;
	}
	print_big(decompressed, original_size);

	// COMP_DEBUG("-----DECOMPRESSING DONE-----\n");

	// COMP_DEBUG("-----COPYING DATA(2)-----\n");
	remaining = original_size;
	while (remaining) {
		size_t io_size;
		mem_offs = 0;
		prp_offs++;
		if (prp_offs == 1) {
			paddr = kv_io_cmd_value_prp(cmd, 1);
		} else if (prp_offs == 2) {
			paddr = kv_io_cmd_value_prp(cmd, 2);
			if (remaining > PAGE_SIZE) {
				paddr_list = kmap_atomic_pfn(PRP_PFN(paddr)) +
					     (paddr & PAGE_OFFSET_MASK);
				paddr = paddr_list[prp2_offs++];
			}
		} else {
			paddr = paddr_list[prp2_offs++];
		}

		vaddr = kmap_atomic_pfn(PRP_PFN(paddr));

		io_size = min_t(size_t, remaining, PAGE_SIZE);

		if (paddr & PAGE_OFFSET_MASK) { // 일반 block io면 언제 여기에 해당?
			mem_offs = paddr & PAGE_OFFSET_MASK;
			if (io_size + mem_offs > PAGE_SIZE)
				io_size = PAGE_SIZE - mem_offs;
		}
		// COMP_DEBUG("offset: %ld, io_size: %ld\n", offset, io_size);
		// COMP_DEBUG("vaddr: %p, mem_offs: %ld\n", vaddr, mem_offs);
		memcpy(vaddr + mem_offs, decompressed, io_size);
		remaining -= io_size;
		offset += io_size;
	}
	// COMP_DEBUG("-----COPYING DONE(2)-----\n");
	vfree(data);
	vfree(decompressed);
	data = NULL;
	decompressed = NULL;
	return status;
}
#endif
static unsigned int __do_perform_kv_io(struct kv_ftl *kv_ftl, struct nvme_kv_command cmd,
				       unsigned int *status)
{
	size_t offset, check_offs;
	size_t data_offs = 0;
	size_t length, remaining;
	size_t compressed_size = 0;
	int prp_offs = 0;
	int prp2_offs = 0;
	u64 paddr;
	u64 *paddr_list = NULL;
	size_t mem_offs = 0;
	size_t new_offset = 0;
	struct mapping_entry entry;
	int is_insert = 0;
	char *decompressed;

	entry = get_mapping_entry(kv_ftl, cmd);
	offset = entry.mem_offset;

	if (cmd.common.opcode == nvme_cmd_kv_store) {
#ifdef COMPRESSION
		if ((compressed_size = try_to_compress(cmd)))
			length = compressed_size;
		else
			length = cmd_value_length(cmd);
#else
		length = cmd_value_length(cmd);
#endif
		// length = cmd_value_length(cmd);
		if (entry.mem_offset == -1) { // entry doesn't exist -> is insert
			new_offset = allocate_mem_offset(kv_ftl, cmd);
			offset = new_offset;
			check_offs = new_offset;
			is_insert = 1; // is insert
			NVMEV_DEBUG("kv_store insert %s %lu, length %ld\n", cmd.kv_store.key,
				    offset, length);
		} else {
			NVMEV_DEBUG("kv_store update %s %lu, length %ld\n", cmd.kv_store.key,
				    offset, length);

			if (length != entry.length) {
				if (length <= SMALL_LENGTH && entry.length <= SMALL_LENGTH) {
					is_insert = 2; // is update with different length;
				} else {
					NVMEV_ERROR("Length size invalid!!");
				}
			}
		}
	} else if (cmd.common.opcode == nvme_cmd_kv_retrieve) {
		length = cmd_value_length(cmd);
		if (entry.mem_offset == -1) { // kv pair doesn't exist
			NVMEV_DEBUG("kv_retrieve %s no exist\n", cmd.kv_store.key);

			*status = KV_ERR_KEY_NOT_EXIST;
			return 0; // dev_status_code for KVS_ERR_KEY_NOT_EXIST
		} else {
			length = min(entry.length, length);

			NVMEV_DEBUG("kv_retrieve %s exist - length %ld, offset %lu\n",
				    cmd.kv_store.key, length, offset);
		}
	} else if (cmd.common.opcode == nvme_cmd_kv_exist) {
		if (entry.mem_offset == -1) { // kv pair doesn't exist
			NVMEV_DEBUG("kv_exist %s no exist\n", cmd.kv_store.key);

			*status = KV_ERR_KEY_NOT_EXIST;
			return 0; // dev_status_code for KVS_ERR_KEY_NOT_EXIST
		} else {
			NVMEV_DEBUG("kv_exist %s exist\n", cmd.kv_store.key);

			return 0;
		}
	} else if (cmd.common.opcode == nvme_cmd_kv_delete) {
		length = cmd_value_length(cmd);
		if (entry.mem_offset == -1) { // kv pair doesn't exist
			NVMEV_DEBUG("kv_delete %s no exist\n", cmd.kv_store.key);

			*status = KV_ERR_KEY_NOT_EXIST;
			return 0; // dev_status_code for KVS_ERR_KEY_NOT_EXIST
		} else {
			NVMEV_DEBUG("kv_delete %s exist - compressed length %ld, offset %lu\n",
				    cmd.kv_store.key, length, offset);

			delete_mapping_entry(kv_ftl, cmd);
			return 0;
		}
	} else {
		NVMEV_ERROR("Cmd type %d, for key %s but not store or retrieve. return 0\n",
			    cmd.common.opcode, cmd.kv_store.key);

		return 0;
	}
	remaining = length;

	while (remaining) {
		size_t io_size;
		void *vaddr;

		mem_offs = 0;
		prp_offs++;
		if (prp_offs == 1) {
			paddr = kv_io_cmd_value_prp(cmd, 1);
		} else if (prp_offs == 2) {
			paddr = kv_io_cmd_value_prp(cmd, 2);
			if (remaining > PAGE_SIZE) {
				paddr_list = kmap_atomic_pfn(PRP_PFN(paddr)) +
					     (paddr & PAGE_OFFSET_MASK);
				paddr = paddr_list[prp2_offs++];
			}
		} else {
			paddr = paddr_list[prp2_offs++];
		}

		vaddr = kmap_atomic_pfn(PRP_PFN(paddr));

		io_size = min_t(size_t, remaining, PAGE_SIZE);

		/* page offset mask = 1111 1111 1111 */
		if (paddr & PAGE_OFFSET_MASK) { // 일반 block io면 언제 여기에 해당?
			mem_offs = paddr & PAGE_OFFSET_MASK;
			if (io_size + mem_offs > PAGE_SIZE)
				io_size = PAGE_SIZE - mem_offs;
		}
		//COMP_DEBUG("remaining: %ld, mem_offs: %ld, io_size: %ld\n", remaining, mem_offs,
		//    io_size);
		//COMP_DEBUG("memcpy, io_size: %ld\n", io_size);
		// COMP_DEBUG("value: %s\n", data);
		if (cmd.common.opcode == nvme_cmd_kv_store) {
			// snprintf(data, length, "%s", (char *)vaddr + mem_offs);
			// COMP_DEBUG("size difference : %ld\n", length - compressed_size);
			// COMP_DEBUG("-----WRITING DATA-----\n");
			// COMP_DEBUG("memcpy, io_size: %ld\n", io_size);
			// COMP_DEBUG("vaddr: %p, mem_offs: %ld\n", vaddr, mem_offs);
			//print_hex_dump(KERN_INFO, "data: ", DUMP_PREFIX_NONE, 16, 4,vaddr + mem_offs, io_size, false);
			memcpy(nvmev_vdev->storage_mapped + offset, vaddr + mem_offs, io_size);
			// COMP_DEBUG("-----WRITING DONE-----\n");
			remaining -= io_size;
			offset += io_size;
		} else if (cmd.common.opcode == nvme_cmd_kv_retrieve) {
#ifdef COMPRESSION
			if (entry.compressed == true) {
				/* decompress */
				if (decompress(cmd, kv_ftl)) {
					remaining = 0;
				} else {
					COMP_DEBUG("!!!!!!!!!!DECOMPRESS FAIL!!!!!!!!!!\n");
					entry.compressed = false;
				}
			} else {
				COMP_DEBUG("NOT COMPRESSED DATA\n");
				memcpy(vaddr + mem_offs, nvmev_vdev->storage_mapped + offset,
				       io_size);
				remaining -= io_size;
				offset += io_size;
			}
#else
			memcpy(vaddr + mem_offs, nvmev_vdev->storage_mapped + offset, io_size);
			remaining -= io_size;
			offset += io_size;
#endif
		} else {
			NVMEV_ERROR("Wrong KV Command passed to NVMeVirt!!\n");
		}

		kunmap_atomic(vaddr);
	}

	if (paddr_list != NULL)
		kunmap_atomic(paddr_list);

	if (is_insert == 1) { // need to make new mapping
		// COMP_DEBUG("-----COMPRESSED DATA CHECK-----\n");
		// print_big(data, compressed_size);
		// COMP_DEBUG("-----CHECK DONE-----\n");
		// COMP_DEBUG("-----COMPRESSED DATA CHECK(2)-----\n");
		// memset(data, 0, 4096);
		// memcpy(data, nvmev_vdev->storage_mapped + check_offs, compressed_size);
		// print_big(data, compressed_size);
		// COMP_DEBUG("-----DATA CHECK DONE(2)-----\n");
		new_mapping_entry(kv_ftl, cmd, new_offset, compressed_size);
	} else if (is_insert == 2) {
		update_mapping_entry(kv_ftl, cmd);
	}

	if (cmd.common.opcode == nvme_cmd_kv_retrieve)
		return length;

	COMP_DEBUG("%s done\n", __func__);
	return 0;
}

static unsigned int __do_perform_kv_batched_io(struct kv_ftl *kv_ftl, int opcode, char *key,
					       int key_len, char *value, int val_len)
{
	size_t offset;
	size_t new_offset = 0;
	struct mapping_entry entry;
	int is_insert = 0;

	entry = get_mapping_entry_by_key(kv_ftl, key, key_len);
	offset = entry.mem_offset;

	if (opcode == nvme_cmd_kv_store) {
		if (entry.mem_offset == -1) { // entry doesn't exist -> is insert
			NVMEV_DEBUG("kv_store insert %s\n", key);

			new_offset = allocate_mem_offset_by_length(kv_ftl, val_len);
			offset = new_offset;
			is_insert = 1; // is insert
		} else {
			NVMEV_DEBUG("kv_store update %s %lu\n", key, offset);

			if (val_len != entry.length) {
				if (val_len <= SMALL_LENGTH && entry.length <= SMALL_LENGTH) {
					is_insert = 2; // is update with different length;
				} else {
					NVMEV_ERROR("Length size invalid!!");
				}
			}
		}
	} else {
		NVMEV_ERROR("Cmd type %d, for key %s but not store or retrieve. return 0\n", opcode,
			    key);

		return 0;
	}

	NVMEV_DEBUG("Value write length %d to position %lu %s\n", val_len, offset, value);
	memcpy(nvmev_vdev->storage_mapped + offset, value, val_len);

	if (is_insert == 1) { // need to make new mapping
		new_mapping_entry_by_key(kv_ftl, key, key_len, val_len, new_offset);
	}
	// else if (is_insert == 2) {
	// 	update_mapping_entry(cmd);
	// }

	return 0;
}

static unsigned int __do_perform_kv_batch(struct kv_ftl *kv_ftl, struct nvme_kv_command cmd,
					  unsigned int *status)
{
	size_t offset;
	size_t length, remaining;
	int prp_offs = 0;
	int prp2_offs = 0;
	u64 paddr;
	u64 *paddr_list = NULL;
	size_t mem_offs = 0;
	int i;
	struct payload_format *payload;
	char *buffer = NULL;
	char key[20];
	char *value;
	int sub_cmd_cnt;
	int opcode, sub_len, key_len, val_len, payload_offset = 0;

	sub_cmd_cnt = cmd.kv_batch.rsvd4;
	length = cmd_value_length(cmd);

	value = kmalloc(4097, GFP_KERNEL);
	buffer = kmalloc(length, GFP_KERNEL);

	//printk("kv_batch %d %d", sub_cmd_cnt, length);

	remaining = length;
	offset = 0;

	while (remaining) {
		size_t io_size;
		void *vaddr;

		mem_offs = 0;
		prp_offs++;
		if (prp_offs == 1) {
			paddr = kv_io_cmd_value_prp(cmd, 1);
		} else if (prp_offs == 2) {
			paddr = kv_io_cmd_value_prp(cmd, 2);
			if (remaining > PAGE_SIZE) {
				paddr_list = kmap_atomic_pfn(PRP_PFN(paddr)) +
					     (paddr & PAGE_OFFSET_MASK);
				paddr = paddr_list[prp2_offs++];
			}
		} else {
			paddr = paddr_list[prp2_offs++];
		}

		vaddr = kmap_atomic_pfn(PRP_PFN(paddr));

		io_size = min_t(size_t, remaining, PAGE_SIZE);

		if (paddr & PAGE_OFFSET_MASK) { // 일반 block io면 언제 여기에 해당?
			mem_offs = paddr & PAGE_OFFSET_MASK;
			if (io_size + mem_offs > PAGE_SIZE)
				io_size = PAGE_SIZE - mem_offs;
		}

		NVMEV_DEBUG("Value write length %lu to position %lu, io size: %ld, mem_off: %lu\n",
			    remaining, offset, io_size, mem_offs);
		memcpy(buffer + offset, vaddr + mem_offs, io_size);

		kunmap_atomic(vaddr);

		remaining -= io_size;
		offset += io_size;
	}

	/* perform KV IO for sub-payload */
	payload = (struct payload_format *)buffer;
	payload_offset = ALIGN_LEN;
	for (i = 0; i < sub_cmd_cnt; i++) {
		memset(key, 0, 20);
		memset(value, 0, 4097);
		sub_len = 0;
		opcode = payload->batch_head.attr[i].opcode;
		key_len = payload->batch_head.attr[i].keySize;
		val_len = payload->batch_head.attr[i].valueSize;
		sub_len += ((key_len - 1) / ALIGN_LEN + 1) * ALIGN_LEN;
		sub_len += ((val_len - 1) / ALIGN_LEN + 1) * ALIGN_LEN;
		sub_len += ALIGN_LEN;

		memcpy(key, payload->sub_payload + payload_offset, key_len);
		memcpy(value,
		       payload->sub_payload + payload_offset +
			       ((key_len - 1) / ALIGN_LEN + 1) * ALIGN_LEN,
		       val_len);
		payload_offset += sub_len;
		NVMEV_DEBUG("sub-payload %d %d %d %d %s %s", payload->batch_head.attr[i].opcode,
			    key_len, val_len, sub_len, key, value);

		__do_perform_kv_batched_io(kv_ftl, opcode, key, key_len, value, val_len);
	}

	NVMEV_DEBUG("finished kv_batch with %d sub-commands", sub_cmd_cnt);

	if (paddr_list != NULL)
		kunmap_atomic(paddr_list);

	if (value != NULL)
		kfree(value);

	if (buffer != NULL)
		kfree(buffer);

	return 0;
}

unsigned int kv_iter_open(struct kv_ftl *kv_ftl, struct nvme_kv_command cmd, unsigned int *status)
{
	int iter = 0;
	bool flag = false;

	for (iter = 1; iter <= 16; iter++) {
		if (kv_ftl->iter_handle[iter] == NULL) {
			flag = true;
			break;
		}
	}

	if (!flag)
		return 1;

	kv_ftl->iter_handle[iter] = kmalloc(sizeof(struct kv_iter_context), GFP_KERNEL);
	kv_ftl->iter_handle[iter]->buf = kmalloc(32768, GFP_KERNEL);
	kv_ftl->iter_handle[iter]->end = 0;
	kv_ftl->iter_handle[iter]->byteswritten = 0;
	kv_ftl->iter_handle[iter]->bufoffset = 0;
	kv_ftl->iter_handle[iter]->current_pos = 0;
	kv_ftl->iter_handle[iter]->bitmask = cmd.kv_iter_req.iter_bitmask;
	kv_ftl->iter_handle[iter]->prefix = cmd.kv_iter_req.iter_val;

	*status = 0;
	return iter;
}

unsigned int kv_iter_close(struct kv_ftl *kv_ftl, struct nvme_kv_command cmd, unsigned int *status)
{
	int iter = cmd.kv_iter_req.iter_handle;

	if (kv_ftl->iter_handle[iter]) {
		kfree(kv_ftl->iter_handle[iter]->buf);
		kfree(kv_ftl->iter_handle[iter]);

		kv_ftl->iter_handle[iter] = NULL;
	}

	*status = 0;
	return 0;
}

static unsigned int kv_iter_read(struct kv_ftl *kv_ftl, struct nvme_kv_command cmd,
				 unsigned int *status)
{
	int iter = cmd.kv_iter_req.iter_handle;
	struct kv_iter_context *handle = kv_ftl->iter_handle[iter];
	int pos = 0, keylen = 16, buf_offset = 4, nr_keys = 0;
	unsigned int key;
	bool full = false, end = false;
	size_t remaining, mem_offs = 0, offset;
	int prp_offs = 0, prp2_offs = 0;
	u64 paddr;
	u64 *paddr_list = NULL;

	if (handle == NULL) {
		NVMEV_ERROR("Invalid Iterator Handle");
		return 0;
	}

	pos = handle->current_pos;

	while (pos < kv_ftl->hash_slots) {
		if (kv_ftl->kv_mapping_table[pos].mem_offset != -1) {
			memcpy(&key, kv_ftl->kv_mapping_table[pos].key, 4);
			if ((key & handle->bitmask) == (handle->prefix & handle->bitmask)) {
				NVMEV_DEBUG("found %s at %d", kv_ftl->kv_mapping_table[pos].key,
					    pos);

				if ((buf_offset + 4 + keylen) > 1024) {
					full = true;
					break;
				}

				memcpy(handle->buf + buf_offset, &keylen, 4);
				buf_offset += 4;
				memcpy(handle->buf + buf_offset, kv_ftl->kv_mapping_table[pos].key,
				       keylen);
				buf_offset += (keylen + 3) & (~3);

				nr_keys++;
			}
		}

		pos++;
		if (pos == kv_ftl->hash_slots) {
			end = true;
			break;
		}
	}
	memcpy(handle->buf, &nr_keys, 4);

	NVMEV_DEBUG("Iterator read done, buf_offset %d, pos %d", buf_offset, pos);
	handle->current_pos = pos;

	/* Writing buffer to PRP */
	remaining = buf_offset;
	offset = 0;

	while (remaining) {
		size_t io_size;
		void *vaddr;

		mem_offs = 0;
		prp_offs++;
		if (prp_offs == 1) {
			paddr = kv_io_cmd_value_prp(cmd, 1);
		} else if (prp_offs == 2) {
			paddr = kv_io_cmd_value_prp(cmd, 2);
			if (remaining > PAGE_SIZE) {
				paddr_list = kmap_atomic_pfn(PRP_PFN(paddr)) +
					     (paddr & PAGE_OFFSET_MASK);
				paddr = paddr_list[prp2_offs++];
			}
		} else {
			paddr = paddr_list[prp2_offs++];
		}

		vaddr = kmap_atomic_pfn(PRP_PFN(paddr));

		io_size = min_t(size_t, remaining, PAGE_SIZE);

		if (paddr & PAGE_OFFSET_MASK) {
			mem_offs = paddr & PAGE_OFFSET_MASK;
			if (io_size + mem_offs > PAGE_SIZE)
				io_size = PAGE_SIZE - mem_offs;
		}

		NVMEV_DEBUG(
			"Buffer transfer, length %lu from position %lu, io size: %ld, mem_off: %lu\n",
			remaining, offset, io_size, mem_offs);
		memcpy(vaddr + mem_offs, handle->buf + offset, io_size);

		kunmap_atomic(vaddr);

		remaining -= io_size;
		offset += io_size;
	}

	if (paddr_list != NULL)
		kunmap_atomic(paddr_list);

	*status = 0;
	if (end) {
		*status = 0x393;
	}

	return buf_offset;
}

static unsigned int __do_perform_kv_iter_io(struct kv_ftl *kv_ftl, struct nvme_kv_command cmd,
					    unsigned int *status)
{
	if (is_kv_iter_req_cmd(cmd.common.opcode)) {
		if (cmd.kv_iter_req.option & ITER_OPTION_OPEN) {
			return kv_iter_open(kv_ftl, cmd, status);
		} else if (cmd.kv_iter_req.option & ITER_OPTION_CLOSE) {
			return kv_iter_close(kv_ftl, cmd, status);
		}
	} else if (is_kv_iter_read_cmd(cmd.common.opcode)) {
		return kv_iter_read(kv_ftl, cmd, status);
	}

	return 0;
}

/* NOTE implement compression 
 * if __schedule_io_units is guaranteed to come before memcpy 
 */
#ifdef COMPRESSION
cell_mode_t get_compress_time(struct nvme_command *cmd)
{
	struct nvme_kv_command *kvcmd = (struct nvme_kv_command *)cmd;
	void *vaddr, *workmem;
	char *compressed_data;
	int prp_offs = 0;
	int prp2_offs = 0;
	u64 paddr;
	u64 *paddr_list = NULL;
	size_t length, compressed_size, remaining;
	size_t mem_offs = 0;
	size_t offset = 0;
	char *data;
	int output_size;
	unsigned int expected_comprate = 0;

	// COMP_DEBUG("%s start\n", __func__);
	length = cmd_value_length(*kvcmd);
	data = vzalloc(length);
	if (!data) {
		COMP_DEBUG("vzalloc error data\n");
	}

	remaining = length;
	while (remaining) {
		size_t io_size;
		mem_offs = 0;
		prp_offs++;
		if (prp_offs == 1) {
			paddr = kv_io_cmd_value_prp(*kvcmd, 1);
		} else if (prp_offs == 2) {
			paddr = kv_io_cmd_value_prp(*kvcmd, 2);
			if (remaining > PAGE_SIZE) {
				paddr_list = kmap_atomic_pfn(PRP_PFN(paddr)) +
					     (paddr & PAGE_OFFSET_MASK);
				paddr = paddr_list[prp2_offs++];
			}
		} else {
			paddr = paddr_list[prp2_offs++];
		}

		vaddr = kmap_atomic_pfn(PRP_PFN(paddr));

		io_size = min_t(size_t, remaining, PAGE_SIZE);

		if (paddr & PAGE_OFFSET_MASK) { // 일반 block io면 언제 여기에 해당?
			mem_offs = paddr & PAGE_OFFSET_MASK;
			if (io_size + mem_offs > PAGE_SIZE)
				io_size = PAGE_SIZE - mem_offs;
		}
		memcpy(data + offset, vaddr + mem_offs, io_size);
		// COMP_DEBUG("[%s] memoffset: %ld, vaddr: %p\n", __func__, mem_offs, vaddr);
		// COMP_DEBUG("remaining: %ld, mem_offs: %ld, io_size: %ld\n", remaining, mem_offs,
		// 	   io_size);
		remaining -= io_size;
		offset += io_size;
	}
	expected_comprate = ((get_byte_entropy(data, length) / 1024) * 10000) / 8000;
	if (expected_comprate < 5000) {
		// COMP_DEBUG("original size: %ld, original data: %s\n", length, data);
		workmem = vmalloc(LZ4_MEM_COMPRESS);
		if (!workmem) {
			COMP_DEBUG("vmalloc error workmem\n");
		}
		output_size = LZ4_COMPRESSBOUND(length);
		// COMP_DEBUG("output size: %d\n", output_size);
		compressed_data = (char *)vzalloc(output_size);
		if (!compressed_data) {
			COMP_DEBUG("vzalloc error compressed_data\n");
		}
		compressed_size = LZ4_compress_default(data, compressed_data, (int)length,
						       output_size, workmem);
		// COMP_DEBUG("compressing took %llu\n", time1 - time0);
		vfree(compressed_data);
		vfree(workmem);
		vfree(data);
		workmem = NULL;
		data = NULL;
		compressed_data = NULL;
		return MLC;
	} else {
		return QLC;
	}
	// COMP_DEBUG("%s done\n", __func__);
}

/* NOTE implement decompression 
 * if __schedule_io_units is guaranteed to come before memcpy 
 */
cell_mode_t get_decomp_time(struct nvme_command *cmd, struct nvmev_ns *ns)
{
	struct nvme_kv_command *kvcmd = (struct nvme_kv_command *)cmd;
	struct kv_ftl *kv_ftl = (struct kv_ftl *)ns->ftls;
	char *decompressed;
	int i = 0;
	u64 paddr, time0, time1;
	u64 *paddr_list = NULL;
	size_t length, remaining, original_size;
	size_t mem_offs = 0;
	size_t offset = 0;
	char *data;
	struct mapping_entry entry;
	int status = 0;
	/* if compressed, then decompress */

	entry = get_mapping_entry(kv_ftl, *kvcmd);
	if (entry.compressed == true) { /* if entry exists */
		offset = entry.mem_offset;
		length = entry.compressed_size;
		// COMP_DEBUG("KEY: %s\n", kvcmd->kv_store.key);
		// COMP_DEBUG("[%s]: vmalloc length: %ld\n", __func__, length);
		original_size = cmd_value_length(*kvcmd);

		data = (char *)vmalloc(length);
		if (!data) {
			COMP_DEBUG("vmalloc error data\n");
		}
		// COMP_DEBUG("-----GETTING COMPRESSED DATA-----\n");
		memcpy(data, nvmev_vdev->storage_mapped + offset, length);
		// COMP_DEBUG("-----GETTING DONE-----\n");
		COMP_DEBUG("KEY: %s\n", kvcmd->kv_store.key);
		// COMP_DEBUG("Loaded data below: \n");
		// print_big(data, length);
		// COMP_DEBUG("-----DECOMPRESSING-----\n");
		decompressed = (char *)vzalloc(original_size);
		if (!decompressed) {
			COMP_DEBUG("vmalloc error compressed_data\n");
		}
		if ((status = LZ4_decompress_fast(data, decompressed, original_size)) < 0) {
			COMP_DEBUG("[%s]: DECOMPRESS FAIL!!!!!!!!\n", __func__);
		}
		// print_big(decompressed, original_size);

		// COMP_DEBUG("-----DECOMPRESSING DONE-----\n");

		vfree(data);
		vfree(decompressed);
		data = NULL;
		decompressed = NULL;
		return MLC;
	} else {
		return QLC;
	}
}
#endif

bool kv_proc_nvme_io_cmd(struct nvmev_ns *ns, struct nvmev_request *req, struct nvmev_result *ret)
{
	struct nvme_command *cmd = req->cmd;
	u64 time0, time1;
	cell_mode_t cell_mode = MAX;

	switch (cmd->common.opcode) {
	case nvme_cmd_write:
	case nvme_cmd_read:
		ret->nsecs_target = __schedule_io_units(
			cmd->common.opcode, cmd->rw.slba,
			__cmd_io_size((struct nvme_rw_command *)cmd), __get_wallclock(), cell_mode);
		break;
	case nvme_cmd_flush:
		ret->nsecs_target = __schedule_flush(req);
		break;
	case nvme_cmd_kv_store:
#ifdef COMPRESSION
		time0 = ktime_get_ns();
		cell_mode = get_compress_time(cmd);
		time1 = ktime_get_ns();
#endif
		ret->nsecs_target = __schedule_io_units(
			cmd->common.opcode, 0, cmd_value_length(*((struct nvme_kv_command *)cmd)),
			__get_wallclock(), cell_mode);
#ifdef COMPRESSION
		if (cell_mode == MLC) { /* add compression time */
			ret->nsecs_target += (time1 - time0);
		}
#endif
		//COMP_DEBUG("Estimated Time: %llu\n", ret->nsecs_target);
		NVMEV_INFO("%d, %llu, %llu\n", cmd_value_length(*((struct nvme_kv_command *)cmd)),
			   __get_wallclock(), ret->nsecs_target);
		break;
	case nvme_cmd_kv_retrieve:
#ifdef COMPRESSION
		time0 = ktime_get_ns();
		cell_mode = get_decomp_time(cmd, ns);
		time1 = ktime_get_ns();
#endif
		ret->nsecs_target = __schedule_io_units(
			cmd->common.opcode, 0, cmd_value_length(*((struct nvme_kv_command *)cmd)),
			__get_wallclock(), cell_mode);
#ifdef COMPRESSION
		if (cell_mode == MLC) { /* add compression time */
			ret->nsecs_target += (time1 - time0);
		}
#endif
		NVMEV_INFO("%d, %llu, %llu\n", cmd_value_length(*((struct nvme_kv_command *)cmd)),
			   __get_wallclock(), ret->nsecs_target);
		break;
	case nvme_cmd_kv_batch:
		ret->nsecs_target = __schedule_io_units(
			cmd->common.opcode, 0, cmd_value_length(*((struct nvme_kv_command *)cmd)),
			__get_wallclock(), cell_mode);
		NVMEV_INFO("%d, %llu, %llu\n", cmd_value_length(*((struct nvme_kv_command *)cmd)),
			   __get_wallclock(), ret->nsecs_target);
		break;
	default:
		NVMEV_ERROR("%s: command not implemented: %s (0x%x)\n", __func__,
			    nvme_opcode_string(cmd->common.opcode), cmd->common.opcode);
		break;
	}

	return true;
}

bool kv_identify_nvme_io_cmd(struct nvmev_ns *ns, struct nvme_command cmd)
{
	return is_kv_cmd(cmd.common.opcode);
}

unsigned int kv_perform_nvme_io_cmd(struct nvmev_ns *ns, struct nvme_command *cmd, uint32_t *status)
{
	struct kv_ftl *kv_ftl = (struct kv_ftl *)ns->ftls;
	struct nvme_kv_command *kv_cmd = (struct nvme_kv_command *)cmd;

	if (is_kv_batch_cmd(cmd->common.opcode))
		return __do_perform_kv_batch(kv_ftl, *kv_cmd, status);
	else if (is_kv_iter_cmd(cmd->common.opcode))
		return __do_perform_kv_iter_io(kv_ftl, *kv_cmd, status);
	else
		return __do_perform_kv_io(kv_ftl, *kv_cmd, status);
}

void kv_init_namespace(struct nvmev_ns *ns, uint32_t id, uint64_t size, void *mapped_addr,
		       uint32_t cpu_nr_dispatcher)
{
	struct kv_ftl *kv_ftl;
	int i;

	kv_ftl = kmalloc(sizeof(struct kv_ftl), GFP_KERNEL);

	NVMEV_INFO("KV mapping table: %#010lx-%#010x\n",
		   nvmev_vdev->config.storage_start + nvmev_vdev->config.storage_size,
		   KV_MAPPING_TABLE_SIZE);

	kv_ftl->kv_mapping_table =
		memremap(nvmev_vdev->config.storage_start + nvmev_vdev->config.storage_size,
			 KV_MAPPING_TABLE_SIZE, MEMREMAP_WB);

	if (kv_ftl->kv_mapping_table == NULL)
		NVMEV_ERROR("Failed to map kv mapping table.\n");
	else
		memset(kv_ftl->kv_mapping_table, 0x0, KV_MAPPING_TABLE_SIZE);

	if (ALLOCATOR_TYPE == ALLOCATOR_TYPE_BITMAP) {
		kv_ftl->allocator_ops = bitmap_ops;
	} else if (ALLOCATOR_TYPE == ALLOCATOR_TYPE_APPEND_ONLY) {
		kv_ftl->allocator_ops = append_only_ops;
	} else {
		kv_ftl->allocator_ops = append_only_ops;
	}

	if (!kv_ftl->allocator_ops.init(nvmev_vdev->config.storage_size)) {
		NVMEV_ERROR("Allocator init failed\n");
	}

	kv_ftl->hash_slots = KV_MAPPING_TABLE_SIZE / KV_MAPPING_ENTRY_SIZE;
	NVMEV_INFO("Hash slots: %ld\n", kv_ftl->hash_slots);

	for (i = 0; i < kv_ftl->hash_slots; i++) {
		kv_ftl->kv_mapping_table[i].mem_offset = -1;
		kv_ftl->kv_mapping_table[i].next_slot = -1;
		kv_ftl->kv_mapping_table[i].length = -1;
	}

	for (i = 0; i < 16; i++)
		kv_ftl->iter_handle[i] = NULL;

	ns->id = id;
	ns->csi = NVME_CSI_NVM; // Not specifying to KV. Need to support NVM commands too.
	ns->ftls = (void *)kv_ftl;
	ns->size = size;
	ns->mapped = mapped_addr;
	/*register io command handler*/
	ns->proc_io_cmd = kv_proc_nvme_io_cmd;
	/*register CSS specific io command functions*/
	ns->identify_io_cmd = kv_identify_nvme_io_cmd;
	ns->perform_io_cmd = kv_perform_nvme_io_cmd;

	return;
}

void kv_remove_namespace(struct nvmev_ns *ns)
{
	kfree(ns->ftls);
	ns->ftls = NULL;
}
