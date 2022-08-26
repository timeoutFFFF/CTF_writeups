challenge location: https://github.com/Live-CTF/LiveCTF-DEFCON30/tree/master/challenges/open-to-interpretation

In this, the vulnerability occurs because of signed to unsigned conversion error. This error of switch case `d` where position is `int8_t`
``` c
  while ( 2 )
  {
    result = v1;
    if ( v1 < v2 )
    {
      switch ( stack_object[v1] )
      {
        case '?':
          putchar(*((unsigned __int8 *)&stack_object + position + 8));
          goto LABEL_14;
        case 'a':
          if ( --position < 0 )
            return puts("Out of bounds");
          goto LABEL_14;
        case 'd':
          if ( ++position != 0x80 )
            goto LABEL_14;
          return puts("Out of bounds");
        case 's':
          --*((_BYTE *)&stack_object + position + 8);
          goto LABEL_14;
        case 'w':
          ++*((_BYTE *)&stack_object + position + 8);
LABEL_14:
          ++v1;
          continue;
```

In assembly the code in fo case `d` will look like following:
```asm
text:00005555555553DB
.text:00005555555553DB loc_5555555553DB:       ; jumptable 0000555555555363 case 100
.text:00005555555553DB movsx   eax, cs:position
.text:00005555555553E2 add     eax, 1
.text:00005555555553E5 mov     cs:position, al
.text:00005555555553EB movsx   ecx, cs:position ;<------ (1)
.text:00005555555553F2 cmp     ecx, 80h
.text:00005555555553F8 jnz     loc_55555555540F
```
At (1), `movsx` performs move with signed extended so when value of `position` is `0x80`, movsx will set ecx to 0xffffff80 and it won't be equal to 0x80 and cmp to check upper bound will never occur
