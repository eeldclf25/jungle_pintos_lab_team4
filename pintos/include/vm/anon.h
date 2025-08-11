#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"
struct page;
enum vm_type;

struct anon_page {
    /* Initiate the contets of the page */
	vm_initializer *init;
	enum vm_type type;
	void *aux;
	/* Initiate the struct page and maps the pa to the va */
	bool (*page_initializer) (struct page *, enum vm_type, void *kva);

    enum vm_type flag;

    /* swap in, out과 관련된 정보 */
    /* swap space를 페이지 단위로 나눠 비트맵을 통해 할당 여부 관리 */
    /* 페이지는 인덱스를 통해 swap space에 접근 할 수 있음 */
};

void vm_anon_init (void);
bool anon_initializer (struct page *page, enum vm_type type, void *kva);

#endif
