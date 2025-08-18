/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"

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

	file_page->type = type;

	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page = &page->file;

	// /* 현재 페이지 load_arg 불러오기 */
	// struct load_arg *aux = file_page->aux;

	// struct file *file = aux->file;
	// off_t offset = aux->ofs;
	// size_t page_read_bytes = aux->page_read_bytes;
	// size_t page_zero_bytes = aux->page_zero_bytes;

	// file_seek(file, offset);

	// if (file_read(file, kva, page_read_bytes) != page_read_bytes)
	// 	return false;

	// memset(kva + page_read_bytes, 0, page_zero_bytes);

	// return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page = &page->file;

	// /* 수정여부 확인 - 수정된 경우 파일에 반영 */
	// if (pml4_is_dirty(thread_current()->pml4, page->va)) {
	// 	/* 현재 페이지 load_arg 불러오기 */
	// 	struct load_arg *aux = file_page->aux;

	// 	struct file *file = aux->file;
	// 	off_t offset = aux->ofs;
	// 	size_t page_read_bytes = aux->page_read_bytes;

	// 	file_write_at(file, page->va, page_read_bytes, offset);
	// 	pml4_set_dirty(thread_current()->pml4, page->va, 0);
	// }

	// pml4_clear_page(thread_current()->pml4, page->va);
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	// free(page->frame);
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	uint32_t read_bytes = length > file_length (file) ? file_length (file) : length;
	uint32_t zero_bytes = PGSIZE - read_bytes % PGSIZE;
	void *page_start_addr = addr;
	enum vm_type uninit_type = VM_FILE | VM_MARKER_FILE_START;

	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (addr) == 0);
	ASSERT (offset % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;
		struct load_arg *aux = malloc (sizeof (struct load_arg));
		if (aux == NULL) PANIC("mmap_lazy_load_aux malloc failed");

		aux->file = file_reopen (file);
		aux->ofs = offset;
		aux->page_read_bytes = page_read_bytes;
		aux->page_zero_bytes = page_zero_bytes;

		if (!vm_alloc_page_with_initializer (uninit_type, addr, writable, lazy_load_segment, aux)) {
			free (aux);
			return NULL;
		}

		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		offset += page_read_bytes;
		addr += PGSIZE;
		uninit_type = VM_FILE;
	}

	return page_start_addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
}
