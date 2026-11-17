.intel_syntax noprefix
.section .text

.global trona_kernel_invoke_raw
.type trona_kernel_invoke_raw, @function
trona_kernel_invoke_raw:
	push	rbx
	mov	rbx, rdi
	mov	rdi, rsi
	mov	rsi, rdx
	mov	rdx, rcx
	mov	r10, r8
	mov	r8, r9
	mov	r9, [rsp + 16]
	xor	eax, eax
	syscall
	mov	[rbx + 0], rax
	mov	[rbx + 8], rdx
	pop	rbx
	ret
.size trona_kernel_invoke_raw, . - trona_kernel_invoke_raw

/* The descriptor call: argument 0 is the descriptor's user address. */
.global trona_kernel_invoke_desc_raw
.type trona_kernel_invoke_desc_raw, @function
trona_kernel_invoke_desc_raw:
	push	rbx
	mov	rbx, rdi
	mov	rdi, rsi
	mov	rsi, rdx
	mov	rdx, rcx
	mov	r10, r8
	mov	r8, r9
	mov	r9, [rsp + 16]
	mov	eax, 1
	syscall
	mov	[rbx + 0], rax
	mov	[rbx + 8], rdx
	pop	rbx
	ret
.size trona_kernel_invoke_desc_raw, . - trona_kernel_invoke_desc_raw
