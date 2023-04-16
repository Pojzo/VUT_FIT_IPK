x = "00 54 f9 49 40 00 40 01 43 5d 7f 00 00 01 7f 00"
x = x.split()
for i in range(len(x)):
    x[i] = int(x[i], 16)
    if str(x[i]).isprintable():
        print(chr(x[i]), end='')
print()
