# WhileDetect
--
### A python tool for detecting whether there are some while(1) loops in your binary after compiling by GCC

# Usage
--
	python whiledetect.py [binary_path]
	eg:
	python whiledetect.py /opt/nginx/sbin/nginx
  

# Motivation for writing this tool
--
### GCC Bug in a hgih version(4.8.*) :the bug of Compile options "-O2"
### The code mode(fake c):
	for(a=func(b);a!=c;a=func(b)) 
	{
	    ...task_body...
	}
### will be optimized to 
	a=func(b);
	if(a!=c)
	{
	    while(1)
	    {
	        ...task_body...
	    }
	}
### and the code mode above will run in an endless loop

# Problem of false positives of this tool remained
- The initial function "register_tm_clones" which added by gcc automaticly will be detected as the while true code block, maybe it can be eliminated by set a smaller disntance of JUMP_MAX_DISTANCE in the script named `searchwhile.py`
- the code blocks which contain a `CALL` to `EXIT` or `EXCEPTION` syscall will be detected as the while true code block, and this problem remains to be fix by distinguish the target of CALL instructions in the potential code blocks