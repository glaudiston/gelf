# log do a log operation over a base on rax and put the result in the register passed as arg $2
# the result is float
log(){
	# CVTSI2SD Convert Signed Integer to Scalar Double Precision Floating-Point
	#F20F2AC6 	cvtsi2sd %esi,%xmm0
	# CVTTSD2SI — Convert With Truncation Scalar Double Precision Floating-Point Value to SignedInteger
	:
	CVTTSD2SI_XMM0_ESI="f20f2cf0";
}
