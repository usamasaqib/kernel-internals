
## Overview
Create page table mapping for the physical memory for specific physical addresses. Note that it can only be used to populate non-present entries. The virtual and physical addresses have to be aligned on PMD level down. It returns the last physical address mapped.

```c
unsigned long __meminit
kernel_physical_mapping_init(unsigned long paddr_start,
			     unsigned long paddr_end,
			     unsigned long page_size_mask, pgprot_t prot)
{
	return __kernel_physical_mapping_init(paddr_start, paddr_end,
					      page_size_mask, prot, true);
}

static unsigned long __meminit
__kernel_physical_mapping_init(unsigned long paddr_start,
			       unsigned long paddr_end,
			       unsigned long page_size_mask,
			       pgprot_t prot, bool init)
```

## Details

### Stacktrace
The stacktrace upon entry into `__kernel_physical_mapping_init` when mapping the physical addresses is as follows:
```c
gef> bt                                                                                    
__kernel_physical_mapping_init (paddr_start=0x43fe00000, paddr_end=0x440000000, page_size_mask=0xc, prot={pgprot = 0x8000000000000163}, init=init@entry=0x1) at arch/x86/mm/init_64.c:735                                                        

0xffffffff831939af in kernel_physical_mapping_init (paddr_start=<optimized out>, paddr_end=<optimized out>, page_size_mask=<optimized out>, prot=<optimized out>, prot@entry={pgprot = 0x8000000000000163}) at arch/x86/mm/init_64.c:787
0xffffffff81c6e1b7 in init_memory_mapping (start=start@entry=0x43fe00000, end=<optimized out>, prot={pgprot = 0x8000000000000163}) at arch/x86/mm/init.c:549
0xffffffff8313c865 in init_range_memory_mapping (r_start=r_start@entry=0x43fe00000, r_end=0x440000000) at arch/x86/mm/init.c:591 
0xffffffff8313cbe2 in memory_map_top_down (map_start=0x100000, map_end=0x440000000) at arch/x86/mm/init.c:670 
init_mem_mapping () at arch/x86/mm/init.c:791
0xffffffff83125297 in setup_arch (cmdline_p=cmdline_p@entry=0xffffffff82a03f00) at arch/x86/kernel/setup.c:1040
0xffffffff831199fd in start_kernel () at init/main.c:905
0xffffffff83124148 in x86_64_start_reservations (real_mode_data=real_mode_data@entry=0x14770 <entry_stack_storage+1904> <error: Cannot access memory at address 0x14770>) at arch/x86/kernel/head64.c:555
0xffffffff83124286 in x86_64_start_kernel (real_mode_data=0x14770 <entry_stack_storage+1904> <error: Cannot access memory at address 0x14770>) at arch/x86/kernel/head64.c:536
0xffffffff810001d2 in secondary_startup_64 () at arch/x86/kernel/head_64.S:461 
0x0000000000000000 in ?? () 
```

The [e820__memblock_setup](https://elixir.bootlin.com/linux/v6.8.9/source/arch/x86/kernel/e820.c#L1316) in `setup_arch` adds all `e820_table` entries to memblock.
From this point on the kernel interacts with the memblock API to access physical memory.

The kernel calls [init_range_memory_mapping](https://elixir.bootlin.com/linux/v6.8.9/source/arch/x86/mm/init.c#L571) via [memory_map_top_down](https://elixir.bootlin.com/linux/v6.8.9/source/arch/x86/mm/init.c#L628), which loops over each PFN in the [memblock](./memblock.md) regions, and maps each region falling within the provided range.

```c
/*
 * We need to iterate through the E820 memory map and create direct mappings
 * for only E820_TYPE_RAM and E820_KERN_RESERVED regions. We cannot simply
 * create direct mappings for all pfns from [0 to max_low_pfn) and
 * [4GB to max_pfn) because of possible memory holes in high addresses
 * that cannot be marked as UC by fixed/variable range MTRRs.
 * Depending on the alignment of E820 ranges, this may possibly result
 * in using smaller size (i.e. 4K instead of 2M or 1G) page tables.
 *
 * init_mem_mapping() calls init_range_memory_mapping() with big range.
 * That range would have hole in the middle or ends, and only ram parts
 * will be mapped in init_range_memory_mapping().
 */
static unsigned long __init init_range_memory_mapping(
					   unsigned long r_start,
					   unsigned long r_end)
{
	unsigned long start_pfn, end_pfn;
	unsigned long mapped_ram_size = 0;
	int i;

	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, NULL) {
		u64 start = clamp_val(PFN_PHYS(start_pfn), r_start, r_end);
		u64 end = clamp_val(PFN_PHYS(end_pfn), r_start, r_end);
		if (start >= end)
			continue;

		/*
		 * if it is overlapping with brk pgt, we need to
		 * alloc pgt buf from memblock instead.
		 */
		can_use_brk_pgt = max(start, (u64)pgt_buf_end<<PAGE_SHIFT) >=
				    min(end, (u64)pgt_buf_top<<PAGE_SHIFT);
		init_memory_mapping(start, end, PAGE_KERNEL);
		mapped_ram_size += end - start;
		can_use_brk_pgt = true;
	}

	return mapped_ram_size;
}
```

The macro `for_each_mem_pfn` expands as follows:
```c
// preprossed macro : for_each_mem_pfn_range
 for (i = -1, __next_mem_pfn_range(&i, (1 << 6), &start_pfn, &end_pfn, ((void *)0)); i >= 0; __next_mem_pfn_range(&i, (1 << 6), &start_pfn, &end_pfn, ((void *)0)))
```
where `__next_mem_pfn_range` loops over all the regions memblock.memory.regions[] and returns the page frame number of the first region matching the node_id or any if MAX_NUMNODES is passed.

```c
// This functions loops over all the regions memblock.memory.regions[] and 
// returns the page frame number of the first region matching the node_id 
// or any if MAX_NUMNODES is passed.
void __init_memblock __next_mem_pfn_range(int *idx, int nid,
				unsigned long *out_start_pfn,
				unsigned long *out_end_pfn, int *out_nid)
{
	struct memblock_type *type = &memblock.memory;
	struct memblock_region *r;
	int r_nid;

	while (++*idx < type->cnt) {
		r = &type->regions[*idx];
		r_nid = memblock_get_region_node(r);

		if (PFN_UP(r->base) >= PFN_DOWN(r->base + r->size))
			continue;
		if (nid == MAX_NUMNODES || nid == r_nid)
			break;
	}
	if (*idx >= type->cnt) {
		*idx = -1;
		return;
	}

	if (out_start_pfn)
		*out_start_pfn = PFN_UP(r->base);
	if (out_end_pfn)
		*out_end_pfn = PFN_DOWN(r->base + r->size);
	if (out_nid)
		*out_nid = r_nid;
}
```

By looping over the ranges in memblocks we avoid creating mappings for holes in memory.

As explained above `init_range_memory_mapping` loops over each memblock region, checks if it covers the desired range `[r_start, r_end]`. If it falls in the desired range then it calls `init_memory_mapping` with `PFN_PHYS(start)` and `PFN_PHYS(end)`.

#### PFN_PHYS
```c
#define PFN_PHYS(x) ((phys_addr_t)(x) << PAGE_SHIFT)
```
Convert a PFN (page frame number) to a physical address
### init_memory_mapping
```c
/*
 * Setup the direct mapping of the physical memory at PAGE_OFFSET.
 * This runs before bootmem is initialized and gets pages directly from
 * the physical memory. To access them they are temporarily mapped.
 */
unsigned long __ref init_memory_mapping(unsigned long start,
					unsigned long end, pgprot_t prot)
{
	struct map_range mr[NR_RANGE_MR];
	unsigned long ret = 0;
	int nr_range, i;

	pr_debug("init_memory_mapping: [mem %#010lx-%#010lx]\n",
	       start, end - 1);

	memset(mr, 0, sizeof(mr));
	nr_range = split_mem_range(mr, 0, start, end);

	for (i = 0; i < nr_range; i++)
		ret = kernel_physical_mapping_init(mr[i].start, mr[i].end,
						   mr[i].page_size_mask,
						   prot);

	add_pfn_range_mapped(start >> PAGE_SHIFT, ret >> PAGE_SHIFT);

	return ret >> PAGE_SHIFT;
}
```
This function is responsible for setting up direct mapping of physical memory at PAGE_OFFSET.

```
#define PAGE_OFFSET ((unsigned long)__PAGE_OFFSET)
#define __PAGE_OFFSET page_offset_base
```
>`page_offset_base` is 0xffff888000000000. This is where physical mapping of the entire memory starts from.

`init_memory_mapping` receives `start` and `end` as the range to map. These are the **physical** addresses to map.
The protections of the pages is set to `PAGE_KERNEL`.

Given some range `[start, end]` this function invokes `split_mem_range` which builds an array of `struct map_range` describing which page sizes should be used for specific sub-ranges based on certain rules. 
For example an invocation `init_memory_mapping(0x00100000, 0xbffdcfff, PAGE_KERNEL)` would result in a `struct map_range` array from `split_mem_range` as follows:
```c
# Use 4K size pages from 0x100000 - 0x200000
map_range{start: 0x100000, end: 0x200000, page_size: 0x4k} 
# Use 2M size pages from 0x200000 - 0x40000000
map_range{start: 0x200000, end: 0x40000000, page_size: 0x2M}
# Use 1G size pages from 0x40000000 - 0x80000000
map_range{start: 0x40000000, end: 0x80000000, page_size: 0x1G}
# Use 2M size pages from 0x80000000 - 0xbfe00000
map_range{start: 0x80000000, end: 0xbfe00000, page_size: 0x2M}
# Use 4K size pages from 0xbfe00000 - 0xbffdd000
map_range{start: 0xbfe00000, end: 0xbffdd000, page_size: 0x4k}
```
The algorithm to decide this split depends on various KConfig values and architecture.

The `init_memory_mapping` function loops over this array of `struct map_range` and call `kernel_physical_mapping_init` on each.
```c
for (i = 0; i < nr_range; i++)
		ret = kernel_physical_mapping_init(mr[i].start, mr[i].end,
						   mr[i].page_size_mask,
						   prot);
```
#### PAGE_KERNEL
The macro is defined as follows
```c
#define PAGE_KERNEL __pgprot_mask(__PAGE_KERNEL | _ENC)
#define __PAGE_KERNEL (__PP|__RW| 0|___A|__NX|___D| 0|___G)

#define __pgprot_mask(x) __pgprot((x) & __default_kernel_pte_mask)

#define _AT(T, X) ((T)(X))

#define __PP _PAGE_PRESENT
#define _PAGE_PRESENT (_AT(pteval_t, 1) << _PAGE_BIT_PRESENT)
#define _PAGE_BIT_PRESENT 0

#define __RW _PAGE_RW
#define _PAGE_RW (_AT(pteval_t, 1) << _PAGE_BIT_RW)
#define _PAGE_BIT_RW 1

#define ___A _PAGE_ACCESSED
#define _PAGE_ACCESSED (_AT(pteval_t, 1) << _PAGE_BIT_ACCESSED)
#define _PAGE_BIT_ACCESSED 5

#define __NX _PAGE_NX
#define _PAGE_NX (_AT(pteval_t, 1) << _PAGE_BIT_NX)
#define _PAGE_BIT_NX 63

#define ___D _PAGE_DIRTY
#define _PAGE_DIRTY (_AT(pteval_t, 1) << _PAGE_BIT_DIRTY)
#define _PAGE_BIT_DIRTY 6

#define ___G _PAGE_GLOBAL
#define _PAGE_GLOBAL (_AT(pteval_t, 1) << _PAGE_BIT_GLOBAL)
#define _PAGE_BIT_GLOBAL 8

#define _ENC _PAGE_ENC
#define _PAGE_ENC (_AT(pteval_t, sme_me_mask))
```

Completely preprocessed it would look like:
```c
(1 << 0 | 1 << 1 | 0 | 1 << 5 | 1 << 63 | 1 << 6 | 0 | 1 << 8 | 0) & 0xffffffffffffffff

// 0xffffffffffffffff is the value __default_kernel_pte_mask
```

This macro defines the page protection bits. More details regarding paging can be found [here](https://wiki.osdev.org/Paging).

### kernel_physical_mapping_init
```c
/*
 * Create page table mapping for the physical memory for specific physical
 * addresses. Note that it can only be used to populate non-present entries.
 * The virtual and physical addresses have to be aligned on PMD level
 * down. It returns the last physical address mapped.
 */
unsigned long __meminit
kernel_physical_mapping_init(unsigned long paddr_start,
			     unsigned long paddr_end,
			     unsigned long page_size_mask, pgprot_t prot)
{
	return __kernel_physical_mapping_init(paddr_start, paddr_end,
					      page_size_mask, prot, true);
}
```

The function receives the start of the physical address range to map, the end of the physical address range to map, the page size mask (this is a mask of allowed page sizes), and the protection bits.

-----
#### Short detour: Paging theory
Details of paging on x86_64 can be found here:
- https://zolutal.github.io/understanding-paging/

This section just provides a brief explanation for quick reference. `x86_64` uses 4-level page tables. 5-level is also possible but ignored here and in subsequent code analysis.


![[Pasted image 20240927164245.png]]

Bits 47-39 provide index into PGD, 38-30 into PUD, 29-21 into PMD, 20-12 in PTE, and the lowest 12 bits specify the offset into the page.

![[Pasted image 20240927165227.png]]
Each table has 2^9 = 512 entries. 2^9 because there are 9 bits each, example `[20, 12]`
- An entry in PGD table can map 1 << 39 = 512 GB of memory, so a 48 bit address space can theoretically map 256 TB
	- 1 bit is used to distinguish kernel addresses from userspace addresses, so the address space on linux is constrained to 128 TB (2^47)
	- This means that for the top level PGD 256 entries are kernel entries and the remaining 256 entries map userspace.
- An entry PUD table can map 1 <<< 30 = 1 GB of memory.
- An entry in PMD can map 1 << 21 = 2 MB of memory.
- An entry in the PTE table can map 1 << 12 = 4KB of memory.

-----
#### `__kernel_physical_mapping_init`

This function does the actual mapping of the provided physical address range. It takes one extra argument `bool init`, which is hardcoded to `true` when invoked in our stacktrace.

```c
static unsigned long __meminit
__kernel_physical_mapping_init(unsigned long paddr_start,
			       unsigned long paddr_end,
			       unsigned long page_size_mask,
			       pgprot_t prot, bool init)
{
	bool pgd_changed = false;
	unsigned long vaddr, vaddr_start, vaddr_end, vaddr_next, paddr_last;

	paddr_last = paddr_end;
	vaddr = (unsigned long)__va(paddr_start);
	vaddr_end = (unsigned long)__va(paddr_end);
	vaddr_start = vaddr;

	for (; vaddr < vaddr_end; vaddr = vaddr_next) {
		// This function translates to:
		// init_mm->pgd + ((vaddr >> 39) & (512 - 1))
		// The unpacking is explained below in the appendix.
		pgd_t *pgd = pgd_offset_k(vaddr);
		p4d_t *p4d;

		// Since each entry in the PGD can map PGDIR_SIZE=512GB of address
		// So the next entry in the PGD table will be vaddr+512GB.
		// We mask by PGDIR_MASK (~0x7fffffffff) so only the relevant bits
		// are considered.
		vaddr_next = (vaddr & PGDIR_MASK) + PGDIR_SIZE;

		// Appendix contains information on pgd_val.
		// Check to see if mapping already performed, i.e. this address has a
		// PGD table entry, thus holds an address to a lower level table.
		if (pgd_val(*pgd)) {
			// pgd_page_vaddr virtualizes the physical address present
			// at the slot `pgd` with `__va`.
			p4d = (p4d_t *)pgd_page_vaddr(*pgd);
			paddr_last = phys_p4d_init(p4d, __pa(vaddr),
						   __pa(vaddr_end),
						   page_size_mask,
						   prot, init);
			continue;
		}

		/* No mapping present for this address in PGD table. */
		// Minor details on alloc_low_page in appendix
		//
		// Allocate a page to hold the P4D/PUD table.
		// Incase of 4 level page table mapping this would be the PUD
		// as we will see in the `phys_p4d_init` function.
		p4d = alloc_low_page();
		// if pgtable_l5_enabled() is false, i.e. 5-level pagetable are
		// not enabled then this function immediately calls phys_pud_init
		// with the same arguments.
		// phys_pud_init create PUD level page table mappings for the given 
		// address.
		paddr_last = phys_p4d_init(p4d, __pa(vaddr), __pa(vaddr_end),
					   page_size_mask, prot, init);

		// page_table_lock protects page tables. This is required because
		// we are now going to write the **physical address** of `p4d` from
		// above into the appropriate slot in the PGD table.
		spin_lock(&init_mm.page_table_lock);
		if (pgtable_l5_enabled())
			pgd_populate_init(&init_mm, pgd, p4d, init);
		else
			// Write the p4d address into the appropriate slot in the PGD table
			// The function is describe in more detail in the appendix
			//
			// With 4-level pagetables p4d_offset just returns pgd. This
			// is because the call above pgd_offset_k(vaddr) already set `pgd`
			// to the correct slot.
			p4d_populate_init(&init_mm, p4d_offset(pgd, vaddr),
					  (pud_t *) p4d, init);

		spin_unlock(&init_mm.page_table_lock);
		pgd_changed = true;
	}

	// this function does not do anything at this stage
	if (pgd_changed)
		sync_global_pgds(vaddr_start, vaddr_end - 1);

	return paddr_last;
}
```

The function coverts the physical address received to virtual address. This is done via the macro `__va` which adds the physical address to the `PAGE_OFFSET`.

```c
#define __va(x) ((void *)((unsigned long)(x)+PAGE_OFFSET))
vaddr = (unsigned long)__va(paddr_start);
vaddr_end = (unsigned long)__va(paddr_end);
```

The function then loops over the virtual address range with a step size of `PGDIR_SIZE`. 
```c
#define _AC(X, Y) __AC(X,Y)
#define PGDIR_SIZE (_AC(1, UL) << PGDIR_SHIFT)
#define PGDIR_SHIFT pgdir_shift
```

The details of the mapping are covered in the code and the comments above.

#### `phys_pud_init`
```c
/*
 * Create PUD level page table mapping for physical addresses. The virtual
 * and physical address do not have to be aligned at this level. KASLR can
 * randomize virtual addresses up to this level.
 * It returns the last physical address mapped.
 */
static unsigned long __meminit
phys_pud_init(pud_t *pud_page, unsigned long paddr, unsigned long paddr_end,
	      unsigned long page_size_mask, pgprot_t _prot, bool init)
{
	unsigned long pages = 0, paddr_next;
	unsigned long paddr_last = paddr_end;
	unsigned long vaddr = (unsigned long)__va(paddr);
	// pud_index gets us the slot in the PUD table holding the physical address
	// to the next level pagetable for this vaddr.
	// We want to start mapping 
	// It is simply defined as:
	// pud_index is explained in Appendix B.
	int i = pud_index(vaddr);

	// Start looping from the current slot and create mappings for
	// all subsequent slots.
	for (; i < PTRS_PER_PUD; i++, paddr = paddr_next) {
		pud_t *pud;
		pmd_t *pmd;
		pgprot_t prot = _prot;

		vaddr = (unsigned long)__va(paddr);

		// Get a pointer to the slot holding the physical address
		// of the next level page table for this virtual address.
		pud = pud_page + pud_index(vaddr);

		// The next address to map will be 1GB from (vaddr & PUD_MASK),
		// since that is the start of the 1GB address range the next PUD slot
		// can map.
		paddr_next = (paddr & PUD_MASK) + PUD_SIZE;

		if (paddr >= paddr_end) {
			if (!after_bootmem &&
			    !e820__mapped_any(paddr & PUD_MASK, paddr_next,
					     E820_TYPE_RAM) &&
			    !e820__mapped_any(paddr & PUD_MASK, paddr_next,
					     E820_TYPE_RESERVED_KERN))
				set_pud_init(pud, __pud(0), init);
			continue;
		}

		// pud_none evaluates to a check to see if the accessed or dirty
		// bits are set for the physicall address `*pud`.
		// See appendix B for details of pud_none.
		if (!pud_none(*pud)) {
			// pud_leaf just checks if _PAGE_PRESENT and _PAGE_PSE are the
			// only bits set for this address. _PAGE_PSE is bit 7 and if 
			// set to 1 indicates a 1GB page.
			// PSE stands for Page Size Extension. 
			if (!pud_leaf(*pud)) {
				// `pmd_offset` with the second argument 0 returns the
				// virtual address of the PMD page table. 
				// Appendix B unpacks pmd_offset
				pmd = pmd_offset(pud, 0);
				paddr_last = phys_pmd_init(pmd, paddr,
							   paddr_end,
							   page_size_mask,
							   prot, init);
				continue;
			}
			/*
			 * If we are ok with PG_LEVEL_1G mapping, then we will
			 * use the existing mapping.
			 *
			 * Otherwise, we will split the gbpage mapping but use
			 * the same existing protection  bits except for large
			 * page, so that we don't violate Intel's TLB
			 * Application note (317080) which says, while changing
			 * the page sizes, new and old translations should
			 * not differ with respect to page frame and
			 * attributes.
			 */
			if (page_size_mask & (1 << PG_LEVEL_1G)) {
				if (!after_bootmem)
					pages++;
				paddr_last = paddr_next;
				continue;
			}

			// If we don't want PG_LEVEL_1G mapping and a mapping already
			// exists, then we split the 1GB page.
			// Details in appendix B
			prot = pte_pgprot(pte_clrhuge(*(pte_t *)pud));
		}

		// If PG_LEVEL_1G mapping is allowed then we add the current paddr
		// we are working with into the appropriate slot pointed to by `pud`.
		if (page_size_mask & (1<<PG_LEVEL_1G)) {
			pages++;
			spin_lock(&init_mm.page_table_lock);
			set_pud_init(pud,
				     pfn_pud(paddr >> PAGE_SHIFT, prot_sethuge(prot)),
				     init);
			spin_unlock(&init_mm.page_table_lock);
			paddr_last = paddr_next;
			continue;
		}

		// If PG_LEVEL_1G mapping is NOT allowed, and `pud_none == 1`,
		// then allocate a page for the PMD page table and invoke 
		// `phys_pmd_init` to perform the mapping in PMD.
		pmd = alloc_low_page();
		paddr_last = phys_pmd_init(pmd, paddr, paddr_end,
					   page_size_mask, prot, init);

		spin_lock(&init_mm.page_table_lock);
		// Once PMD is mapped call `pud_populate_init` to set the mapping
		// for this slot in the PUD page table. `pud_populate_init` is the
		// same as `p4d_populate_init` covereted in appendix A.
		pud_populate_init(&init_mm, pud, pmd, init);
		spin_unlock(&init_mm.page_table_lock);
	}

	update_page_count(PG_LEVEL_1G, pages);

	return paddr_last;
}
```
Starting at the slot for the given `paddr` in the PUD page table, this function iterates over all slots and creates a mapping for them. The mapping is either PG_LEVEL_1G mapping if that is specified in the page_size_mask, otherwise it calls other functions to create mappings for the address in lower level page tables. These page tables are allocated if not present. 

#### `phys_pmd_init`
```c
/*
 * Create PMD level page table mapping for physical addresses. The virtual
 * and physical address have to be aligned at this level.
 * It returns the last physical address mapped.
 */
static unsigned long __meminit
phys_pmd_init(pmd_t *pmd_page, unsigned long paddr, unsigned long paddr_end,
	      unsigned long page_size_mask, pgprot_t prot, bool init)
{
	unsigned long pages = 0, paddr_next;
	unsigned long paddr_last = paddr_end;

	int i = pmd_index(paddr);

	for (; i < PTRS_PER_PMD; i++, paddr = paddr_next) {
		pmd_t *pmd = pmd_page + pmd_index(paddr);
		pte_t *pte;
		pgprot_t new_prot = prot;

		paddr_next = (paddr & PMD_MASK) + PMD_SIZE;
		if (paddr >= paddr_end) {
			if (!after_bootmem &&
			    !e820__mapped_any(paddr & PMD_MASK, paddr_next,
					     E820_TYPE_RAM) &&
			    !e820__mapped_any(paddr & PMD_MASK, paddr_next,
					     E820_TYPE_RESERVED_KERN))
				set_pmd_init(pmd, __pmd(0), init);
			continue;
		}

		if (!pmd_none(*pmd)) {
			if (!pmd_large(*pmd)) {
				spin_lock(&init_mm.page_table_lock);
				pte = (pte_t *)pmd_page_vaddr(*pmd);
				paddr_last = phys_pte_init(pte, paddr,
							   paddr_end, prot,
							   init);
				spin_unlock(&init_mm.page_table_lock);
				continue;
			}
			/*
			 * If we are ok with PG_LEVEL_2M mapping, then we will
			 * use the existing mapping,
			 *
			 * Otherwise, we will split the large page mapping but
			 * use the same existing protection bits except for
			 * large page, so that we don't violate Intel's TLB
			 * Application note (317080) which says, while changing
			 * the page sizes, new and old translations should
			 * not differ with respect to page frame and
			 * attributes.
			 */
			if (page_size_mask & (1 << PG_LEVEL_2M)) {
				if (!after_bootmem)
					pages++;
				paddr_last = paddr_next;
				continue;
			}
			new_prot = pte_pgprot(pte_clrhuge(*(pte_t *)pmd));
		}

		if (page_size_mask & (1<<PG_LEVEL_2M)) {
			pages++;
			spin_lock(&init_mm.page_table_lock);
			set_pmd_init(pmd,
				     pfn_pmd(paddr >> PAGE_SHIFT, prot_sethuge(prot)),
				     init);
			spin_unlock(&init_mm.page_table_lock);
			paddr_last = paddr_next;
			continue;
		}

		pte = alloc_low_page();
		paddr_last = phys_pte_init(pte, paddr, paddr_end, new_prot, init);

		spin_lock(&init_mm.page_table_lock);
		pmd_populate_kernel_init(&init_mm, pmd, pte, init);
		spin_unlock(&init_mm.page_table_lock);
	}
	update_page_count(PG_LEVEL_2M, pages);
	return paddr_last;
}
```
`phys_pmd_init` is exactly the same as `phys_pud_init` so its details are not examined in detail.

#### `phys_pte_init`
This is the last function called when creating a mapping. This function creates a mapping for a 4K page given some address range.

```c

/*
 * Create PTE level page table mapping for physical addresses.
 * It returns the last physical address mapped.
 */
static unsigned long __meminit
phys_pte_init(pte_t *pte_page, unsigned long paddr, unsigned long paddr_end,
	      pgprot_t prot, bool init)
{
	unsigned long pages = 0, paddr_next;
	unsigned long paddr_last = paddr_end;
	pte_t *pte;
	int i;

	pte = pte_page + pte_index(paddr);
	i = pte_index(paddr);

	for (; i < PTRS_PER_PTE; i++, paddr = paddr_next, pte++) {
		paddr_next = (paddr & PAGE_MASK) + PAGE_SIZE;
		if (paddr >= paddr_end) {
			if (!after_bootmem &&
			    !e820__mapped_any(paddr & PAGE_MASK, paddr_next,
					     E820_TYPE_RAM) &&
			    !e820__mapped_any(paddr & PAGE_MASK, paddr_next,
					     E820_TYPE_RESERVED_KERN))
				set_pte_init(pte, __pte(0), init);
			continue;
		}

		/*
		 * We will re-use the existing mapping.
		 * Xen for example has some special requirements, like mapping
		 * pagetable pages as RO. So assume someone who pre-setup
		 * these mappings are more intelligent.
		 */
		if (!pte_none(*pte)) {
			if (!after_bootmem)
				pages++;
			continue;
		}

		if (0)
			pr_info("   pte=%p addr=%lx pte=%016lx\n", pte, paddr,
				pfn_pte(paddr >> PAGE_SHIFT, PAGE_KERNEL).pte);
		pages++;
		set_pte_init(pte, pfn_pte(paddr >> PAGE_SHIFT, prot), init);
		paddr_last = (paddr & PAGE_MASK) + PAGE_SIZE;
	}

	update_page_count(PG_LEVEL_4K, pages);

	return paddr_last;
}
```

Starting at the PTE slot for the provided `paddr` this function loops over all the slots and adds mappings in them for each page `(paddr & PAGE_MASK) + PAGE_SIZE`.

-------
##### pgdir_shift
[This is set to 39](https://elixir.bootlin.com/linux/v6.11/source/arch/x86/boot/compressed/pgtable_64.c#L16) when `CONFIG_X86_5LEVEL` is enabled.

`CONFIG_X86_5LEVEL` allows a kernel to boot with both 4 level and 5 level pagetables. If 5 level pagetables are not supported, as is the case on my QEMU setup, the kernel will boot with 4 level pagetables.

-------
Various other details of the execution are added as comments to the above code block. This remainder of the section will add as an appendix to these comments.

#### Appendix A: `__kernel_physical_mapping_init`

**pgd_offset_k**
Given some address `pgd_offset_k` will return the address of the slot holding the address the next level table, i.e. PUD table, for `init_mm`.
`pgd_index` will acquire the bits 47-39, and use these as an offset into init_mm->pgd PGD table. The address at this offset is the address of PUD table. This returns the virtual address of the PGD table

```c
#define pgd_offset_k(address) pgd_offset(&init_mm, (address))
#define pgd_offset(mm, address) pgd_offset_pgd((mm)->pgd, (address))

static inline pgd_t *pgd_offset_pgd(pgd_t *pgd, unsigned long address)
{
	return (pgd + pgd_index(address));
};

#define pgd_index(a) (((a) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define PTRS_PER_PGD 512
```

**pgd_val**
This provides an accessor to the opaque `pgdval_t` type. More information on the motivation for this pattern in [these docs](https://www.kernel.org/doc/html/v4.14/process/coding-style.html#typedefs).

> Opaqueness and `accessor functions` are not good in themselves. The reason we have them for things like pte_t etc. is that there really is absolutely **zero** portably accessible information there.

```c
#define pgd_val(x) native_pgd_val(x)
#define PGD_ALLOWED_BITS 0xffffffffffffffff

typedef struct { pgdval_t pgd; } pgd_t;

static inline pgdval_t native_pgd_val(pgd_t pgd)
{
	return pgd.pgd & PGD_ALLOWED_BITS;
}
```

**alloc_low_pages**
Allocates a physical page from `pgt_buf` or `memblock`. The return value is the virualized address of the page with `__va`. The page is intended to be immediately mapped by the caller.

**p4d_populate_init**

This function is declared by a macro
```c
#define DEFINE_POPULATE(fname, type1, type2, init)		\
static inline void fname##_init(struct mm_struct *mm,		\
		type1##_t *arg1, type2##_t *arg2, bool init)	\
{								\
	if (init)						\
		fname##_safe(mm, arg1, arg2);			\
	else							\
		fname(mm, arg1, arg2);				\
}

DEFINE_POPULATE(p4d_populate, p4d, pud, init)
```
This expands to the following C code. Here we end up calling `p4d_populate_safe` because `init` is `true`.

```c
static inline __attribute__((__gnu_inline__)) 
    __attribute__((__unused__)) 
    __attribute__((no_instrument_function)) 
    void p4d_populate_init(struct mm_struct *mm, p4d_t *arg1, pud_t *arg2, bool init) 
{ 
    if (init) 
        p4d_populate_safe(mm, arg1, arg2); 
    else p4d_populate(mm, arg1, arg2);
}
```

`p4d_populate_safe` eventually calls into `native_set_p4d`.
```c
#define set_p4d(p4dp, p4d) native_set_p4d(p4dp, p4d)

#define set_p4d_safe(p4dp, p4d) \
({ \
	WARN_ON_ONCE(p4d_present(*p4dp) && !p4d_same(*p4dp, p4d)); \
	set_p4d(p4dp, p4d); \
})

static inline void p4d_populate_safe(struct mm_struct *mm, p4d_t *p4d, pud_t *pud)
{
	// NOP in my QEMU setup.
	paravirt_alloc_pud(mm, __pa(pud) >> PAGE_SHIFT);
	set_p4d_safe(p4d, __p4d(_PAGE_TABLE | __pa(pud)));
}
```

`native_set_p4d` get invoked as follows. 
```c
native_set_p4d(p4d, 
            native_make_p4d(
                ((((pteval_t)(1)) << 0)|(((pteval_t)(1)) << 1)|(((pteval_t)(1)) << 2)|(((pteval_t)(1)) << 5)| 0|(((pteval_t)(1)) << 6)| 0| 0| (((pteval_t)(0ULL)))) | 
                __phys_addr_nodebug((unsigned long)(pud)))
            );
```

`p4d` is the physical address of the slot to write the PUD table address.
The second argument expands to `native_make_p4d(_PAGE_TABLE | __pa(pud))`. `native_make_p4d`, creates and returns the opaque type `p4d_t`. `_PAGE_TABLE` is a macro defining the permission bits of the address
Finally, `__pa` derives the physical address from the virtual one
```c
#define __pa(x) __phys_addr((unsigned long)(x))
#define __phys_addr(x) __phys_addr_nodebug(x)

static __always_inline unsigned long __phys_addr_nodebug(unsigned long x)
{
	unsigned long y = x - __START_KERNEL_map;

	/* use the carry flag to determine if x was < __START_KERNEL_map */
		x = y + ((x > y) ? phys_base : (__START_KERNEL_map - PAGE_OFFSET));

	return x;
}
```
Finally `native_set_p4d` is defined as follows:
```c
static inline void native_set_p4d(p4d_t *p4dp, p4d_t p4d)
{
	pgd_t pgd;

	if (pgtable_l5_enabled() || !IS_ENABLED(CONFIG_PAGE_TABLE_ISOLATION)) {
		WRITE_ONCE(*p4dp, p4d);
		return;
	}

	pgd = native_make_pgd(native_p4d_val(p4d));
	pgd = pti_set_user_pgtbl((pgd_t *)p4dp, pgd);
	WRITE_ONCE(*p4dp, native_make_p4d(native_pgd_val(pgd)));
}
```
The `pti_set_user_pgtbl` functions do not do anything here since we are mapping everything in kernel address space. All physical addresses are mapped starting from `page_offset_base` which places them in the kernel address space.
Otherwise what this function does is that it populates the user pagetables and returns the pgd value that needs to be set in the kernel page tables. With PTI (page table isolation) enabled the kernels maps all of userspace, but the userspace does not map kernel space. This function is responsible for correctly mapping a userspace address in the page tables.

Finally `WRITE_ONCE(*p4dp, native_make_p4d(native_pgd_val(pgd)));` performs the write of the next level page table physical address into the address of the slot provided by `p4dp`.
Note that `p4dp` is the virtual address of the slot.

#### Appendix A: `phys_pud_init`
**pud_index**
```c
#define PUD_SHIFT 30
#define PTRS_PER_PUD 512
static inline unsigned long pud_index(unsigned long address)
{
	return (address >> PUD_SHIFT) & (PTRS_PER_PUD - 1);
}
```
Each PUD page table holds 512 slots. The index in the PUD table is defined by the bits `[38, 30]`, so has 2^9 = 512 slots.

**pud_none**
```c 
#define _PAGE_KNL_ERRATUM_MASK (_PAGE_DIRTY | _PAGE_ACCESSED)
static inline int pud_none(pud_t pud)
{
	return (native_pud_val(pud) & ~(_PAGE_KNL_ERRATUM_MASK)) == 0;
}
```

**pte_clrhuge**
```c
static inline pte_t pte_clear_flags(pte_t pte, pteval_t clear)
{
	pteval_t v = native_pte_val(pte);

	return native_make_pte(v & ~clear);
}

static inline pte_t pte_clrhuge(pte_t pte)
{
	return pte_clear_flags(pte, _PAGE_PSE);
}
```

**`pte_pgprot(pte_clrhuge(*(pte_t *)pud))`**
After preprocessing this macro resolves to:
```c
((pgprot_t) { (pte_flags(pte_clrhuge(*(pte_t *)pud))) } );
```

`pte_flags` just clears all the bits in `pud` except the PTE flags. These are the least significant 12 bits of `pud`

`pte_clrhuge` clears bit 7 of `pud`. This bit is the Page Size Extension (PSE) bit.

**set_pud_init**
The callsite we are analyzing is
```c
set_pud_init(pud,
				pfn_pud(paddr >> page_shift, prot_sethuge(prot)),
				init);

```

```c
static inline void native_set_pud(pud_t *pudp, pud_t pud)
{
	WRITE_ONCE(*pudp, pud);
}

static inline void set_pud_init(pud_t *arg1, pud_t arg2, bool init) { 
	if (init) {
		WARN_ON_ONCE(pud_present(*pudp) && !pud_same(*pudp, pud));
		native_set_pud(arg1, arg2);
	} else 
		native_set_pud(arg1, arg2);

```

**pmd_offset**
This returns the virtual address of the slot in the PMD page table for a particular virtual address.
```c
static inline pmd_t *pmd_offset(pud_t *pud, unsigned long address)
{
	return pud_pgtable(*pud) + pmd_index(address);
}
```

`pmd_index` is straightforward. It gives the index holding the next level page table in the PMD pagetable for a particular address. It is defined as:
```c
#define PMD_SHIFT 21
#define PTRS_PER_PMD 512
static inline unsigned long pmd_index(unsigned long address)
{
	return (address >> PMD_SHIFT) & (PTRS_PER_PMD - 1);
}
```

`pud_pgtable` masks out the lower 12 bits (the protection bits) of a page table entry and returns the virtual address it is pointing to.

```c
#define PAGE_SHIFT 12
#define PAGE_SIZE (_AC(1,UL) << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE-1))

#define __PHYSICAL_MASK_SHIFT 52
#define __PHYSICAL_MASK ((phys_addr_t)((1ULL << __PHYSICAL_MASK_SHIFT) - 1))

#define PHYSICAL_PAGE_MASK (((signed long)PAGE_MASK) & __PHYSICAL_MASK)
#define PTE_PFN_MASK ((pteval_t)PHYSICAL_PAGE_MASK)

// in phys_pud_init `pmd_offset` is called in the a branch where we know
// that _PAGE_PSE is not set, so we take the else branch.
// PTE_PFN_MASK returns a value where bits 51-12 are set to 1 and bits
// 11-0 are set to 0.
static inline pudval_t pud_pfn_mask(pud_t pud)
{
	if (native_pud_val(pud) & _PAGE_PSE)
		return PHYSICAL_PUD_PAGE_MASK;
	else
		return PTE_PFN_MASK;
}


static inline pmd_t *pud_pgtable(pud_t pud)
{
	return (pmd_t *)__va(pud_val(pud) & pud_pfn_mask(pud));
}
```
