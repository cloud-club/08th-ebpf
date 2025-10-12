#define SECTOR_SIZE 512

struct io_stats_t {
    u64 read_bytes;      
    u64 write_bytes;     
    u64 read_count;      
    u64 write_count;     
};

BPF_HASH(io_stats, u32, struct io_stats_t);

TRACEPOINT_PROBE(block, block_rq_complete) {
    u32 key = 0;
    struct io_stats_t *stats = io_stats.lookup(&key);
    struct io_stats_t new_stats = {};
    
    if (stats) {
        new_stats = *stats;
    }
    
    u32 bytes = args->nr_sector * SECTOR_SIZE;

    if (args->rwbs[0] == 'R') {
        new_stats.read_bytes += bytes;
        new_stats.read_count++;
    } else if (args->rwbs[0] == 'W') {
        new_stats.write_bytes += bytes;
        new_stats.write_count++;
    }

    io_stats.update(&key, &new_stats);
    return 0;
}
