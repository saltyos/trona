.section .text

.p2align 2
.global trona_kernel_invoke_raw
.type trona_kernel_invoke_raw, %function
trona_kernel_invoke_raw:
	mov	x9, x0
	mov	x0, x1
	mov	x1, x2
	mov	x2, x3
	mov	x3, x4
	mov	x4, x5
	mov	x5, x6
	mov	x8, #0
	svc	#0
	stp	x0, x1, [x9]
	ret
.size trona_kernel_invoke_raw, . - trona_kernel_invoke_raw

/* The descriptor call: argument 0 is the descriptor's user address. */
.p2align 2
.global trona_kernel_invoke_desc_raw
.type trona_kernel_invoke_desc_raw, %function
trona_kernel_invoke_desc_raw:
	mov	x9, x0
	mov	x0, x1
	mov	x1, x2
	mov	x2, x3
	mov	x3, x4
	mov	x4, x5
	mov	x5, x6
	mov	x8, #1
	svc	#0
	stp	x0, x1, [x9]
	ret
.size trona_kernel_invoke_desc_raw, . - trona_kernel_invoke_desc_raw
