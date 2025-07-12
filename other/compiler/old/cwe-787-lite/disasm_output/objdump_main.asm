0000000100000fa0 _main:
100000fa0: 55                          	pushq	%rbp
100000fa1: 48 89 e5                    	movq	%rsp, %rbp
100000fa4: 31 c0                       	xorl	%eax, %eax
100000fa6: c7 45 fc 00 00 00 00        	movl	$0, -4(%rbp)
100000fad: c6 45 fc 2a                 	movb	$42, -4(%rbp)
100000fb1: 5d                          	popq	%rbp
100000fb2: c3                          	retq
