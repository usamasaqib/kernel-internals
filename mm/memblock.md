Memblocks is one of the way for managing memory during early boot. It arranges memory in a straightforward structure and allows users to add memory and reserve memory.
https://0xax.gitbooks.io/linux-insides/content/MM/linux-mm-1.html

These are the main datatypes used in memblock. `memblock` is the global initialization of the `struct memblock`
```c
/**
 * struct memblock - memblock allocator metadata
 * @bottom_up: is bottom up direction?
 * @current_limit: physical address of the current allocation limit
 * @memory: usable memory regions
 * @reserved: reserved memory regions
 */
struct memblock {
	bool bottom_up;  /* is bottom up direction? */
	phys_addr_t current_limit;
	struct memblock_type memory;
	struct memblock_type reserved;
};

/**
 * struct memblock_type - collection of memory regions of certain type
 * @cnt: number of regions
 * @max: size of the allocated array
 * @total_size: size of all regions
 * @regions: array of regions
 * @name: the memory type symbolic name
 */
struct memblock_type {
	unsigned long cnt;
	unsigned long max;
	phys_addr_t total_size;
	struct memblock_region *regions;
	char *name;
};

static struct memblock_region memblock_memory_init_regions[INIT_MEMBLOCK_MEMORY_REGIONS] __initdata_memblock;
static struct memblock_region memblock_reserved_init_regions[INIT_MEMBLOCK_RESERVED_REGIONS] __initdata_memblock;

struct memblock memblock __initdata_memblock = {
	.memory.regions		= memblock_memory_init_regions,
	.memory.cnt		= 1,	/* empty dummy entry */
	.memory.max		= INIT_MEMBLOCK_MEMORY_REGIONS,
	.memory.name		= "memory",

	.reserved.regions	= memblock_reserved_init_regions,
	.reserved.cnt		= 1,	/* empty dummy entry */
	.reserved.max		= INIT_MEMBLOCK_RESERVED_REGIONS,
	.reserved.name		= "reserved",

	.bottom_up		= false,
	.current_limit		= MEMBLOCK_ALLOC_ANYWHERE,
};


```

On my QEMU setup, after `e820__memblock_setup` has been called, this is the state of the global `memblock` is as follows:
```c
gef> p memblocks  
No symbol "memblocks" in current context.  
gef> p memblock  
$1 = {  
 bottom_up = 0x0,  
 current_limit = 0x100000,  
 memory = {  
   cnt = 0x3,  
   max = 0x80,  
   total_size = 0x3fff7bc00,  
   regions = 0xffffffff83211da0 <memblock_memory_init_regions>,  
   name = 0xffffffff823fc4ea "memory"  
 },  
 reserved = {  
   cnt = 0x2,  
   max = 0x80,  
   total_size = 0x2711000,  
   regions = 0xffffffff832111a0 <memblock_reserved_init_regions>,  
   name = 0xffffffff823ea1b3 "reserved"  
 }  
}

gef> p *memblock.memory.regions@3  
$6 = {  
 [0x0] = {  
   base = 0x1000,  
   size = 0x9e000,  
   flags = MEMBLOCK_NONE,  
   nid = 0x40  
 },  
 [0x1] = {  
   base = 0x100000,  
   size = 0xbfedd000,  
   flags = MEMBLOCK_NONE,  
   nid = 0x40  
 },  
 [0x2] = {  
   base = 0x100000000,  
   size = 0x340000000,  
   flags = MEMBLOCK_NONE,  
   nid = 0x40  
 }  
}
```
As we can see at this stage all the non-reserved physical system memory is divided into 3 memory regions.
