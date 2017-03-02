# WhileDetect
### A python tool for detecting whether there are some while(1) loops in your binary after compiling by GCC

# Motivation for writing this tool
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
