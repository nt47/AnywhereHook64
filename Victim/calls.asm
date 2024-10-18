.data

align   8
extern printLn : proc
extern msg : proc

szText db 'hello,world!',0;



.code


	nop1 proc
	nop
	nop
	nop
	nop
	nop
	ret
	nop1 endp

		hello proc
		sub		rsp, 28h
		lea rcx ,szText
		call	msg
		add		rsp, 28h
		ret
		hello endp


end