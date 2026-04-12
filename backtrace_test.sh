. $(dirname $(realpath $BASH_SOURCE))/backtrace.sh
fn_c() {
	backtrace
}
fn_b() {
	fn_c 4 5 6 7;
}
fn_a() {
	fn_b 1 2 3;
}

fn_a zero $@
