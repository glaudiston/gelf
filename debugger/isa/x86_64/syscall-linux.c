void detect_friendly_instruction(pid_t child, char * friendly_instr)
{
#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_OPEN 2
#define SYS_STAT 4
#define SYS_FSTAT 5
#define SYS_MMAP 9
#define SYS_PIPE 22
#define SYS_DUP2 33
#define SYS_FORK 57
#define SYS_EXECVE 59
#define SYS_EXIT 60
#define SYS_WAIT4 61
#define SYS_GETEUID 107
	char syscall[512];
	char buff[256];
	switch (regs.rax) {
		case SYS_OPEN:
			peek_string(child, (void*)regs.rdi, buff); // filename
			sprintf(friendly_instr, "sys_open(\"%s\", \"%s\")", buff, (char*)&regs.rsi);
			break;
		case SYS_WRITE:
			peek_string(child, (void*)regs.rsi, buff);
			//long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)regs.rsi, 0);
			sprintf(friendly_instr, "sys_write(%lli, \"%s\", %lli)", regs.rdi, buff, regs.rdx);
			break;
		case SYS_READ:
			sprintf(friendly_instr, "sys_read(%lli, 0x%llx, %lli)", regs.rdi, regs.rsi, regs.rdx);
			break;
		case SYS_MMAP:
			sprintf(friendly_instr, "sys_mmap(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx); # alocates %lli bytes using fd %lli", 
				regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9, regs.rsi, regs.r8);
			break;
		case SYS_STAT:
			sprintf(friendly_instr, "sys_stat(%lli)",regs.rsi);
			break;
		case SYS_FSTAT:
			sprintf(friendly_instr, "sys_fstat(%lli, 0x%016llx)",regs.rdi,regs.rsi);
			break;
		case SYS_PIPE:
			sprintf(friendly_instr, "sys_pipe(0x%llx);", regs.rdi);
			break;
		case SYS_DUP2:
			sprintf(friendly_instr, "sys_dup2(%llu,%llu);", regs.rdi, regs.rsi);
			break;
		case SYS_FORK:
			sprintf(friendly_instr, "sys_fork()");
			running_forks++;
			break;
		case SYS_EXECVE:
		{
			char filename[4096];
			char args[4096];
			char env[4096];
			peek_string(child, (void*)regs.rdi, filename);
			peek_array(child, (void*)regs.rsi, args);
			peek_array(child, (void*)regs.rdx, env);
			sprintf(friendly_instr, "sys_execve(file: \"%s\", args: %s, env: %s)", filename, args, env);
			break;
		}
		case SYS_EXIT:
			sprintf(friendly_instr, "sys_exit(%lli)%s",regs.rdi, get_color(""));
			break;
		case SYS_WAIT4:
			sprintf(friendly_instr, "sys_wait4(%lli,%lli,%lli,%lli)",regs.rdi,regs.rsi,regs.rdx, regs.r10);
			break;
		case SYS_GETEUID:
			sprintf(friendly_instr, "sys_geteuid");
			break;
		default:
			sprintf(friendly_instr, "# rax: %lli", regs.rax);
	}
}

