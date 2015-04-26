
int unko = 8;

static int
vmcall1(int n, int arg)
{
    int ret = n;
    asm volatile("xor %%rax, %%rax\n\t"
                 "dec %%rax\n\t"
                 "int $21"
                 :"+a"(ret)
                 :"c"(arg));

    asm volatile("hlt");

    return ret;
}


int _start()
{
    vmcall1(0, 0);
}

