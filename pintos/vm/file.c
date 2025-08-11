/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "userprog/process.h"
#include "threads/vaddr.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	/* 1. 현재 프로세스의 spt 가져오기 */
	struct supplemental_page_table *spt = &thread_current()->spt;
	void *page_start_addr = addr;

	/* 2. length 만큼 페이지 할당하기 */
	while (length > 0) {
		/* 할당하려는 자리에 이미 페이지가 있는지 확인 */
		if (spt_find_page(spt, addr))
			return NULL;

		size_t page_read_bytes = length < PGSIZE ? length : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct load_arg *aux = (struct load_arg *)malloc(sizeof(struct load_arg));
		aux->file = file;
		aux->ofs = offset;
		aux->page_read_bytes = page_read_bytes;
		aux->page_zero_bytes = page_zero_bytes;

		/* 인자(init) 확인 필요 (lazy_load_segment 써야 하는지)!!!!!!!!!!!!!! */
		if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, NULL, aux)) {
			free(aux);
			return NULL;
		}

		addr += PGSIZE;
		offset += page_read_bytes;
		length -= page_read_bytes;
	}

	return page_start_addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
}
