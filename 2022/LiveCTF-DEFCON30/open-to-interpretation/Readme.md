* challenge: https://github.com/Live-CTF/LiveCTF-DEFCON30/tree/master/challenges/open-to-interpretation

In this, the vulnerability occurs because of a signed to an unsigned conversion error. In the following pseudocode, this error occurs in the switch case `d`:
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
          if ( ++position != 0x80 )       ;<-------- (1)
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

At (1), `position` is `int8_t` and compared against unsigned int immediate value 0x80. In assembly the code the comparison code look like the following:

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
At (1), `movsx` performs move with signed extended. It means when the value of `position` is `0x80`, movsx will set `ecx` to 0xffffff80 and it will never be equal to 0x80. The comparison to check the upper bound will never succeed.
