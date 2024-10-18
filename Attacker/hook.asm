.data

align   8

extern printLn : proc
extern msg : proc

extern cpy_entry: qword

szText db 'hello,world!',0;

.code 


	int3 proc
		int 3
		ret
	int3 endp


	node proc
	call hello
	;mov rax,004010F8h
	mov rax,cpy_entry
	jmp rax

	node endp

	hello proc
		sub		rsp, 28h
		lea rcx ,szText
		call	msg
		add		rsp, 28h
		ret
	hello endp

end