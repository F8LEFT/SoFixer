# SoFixer
so修復  
注意看CMakeLists.txt中的 -D__SO64__ 选项，注释掉就是用来修复32位的。

# 使用方法
從so中dump內存， ida腳本
```$cpp
import idaapi
start_address = 0x0000007DB078B000
end_address = 0x0000007DB08DE000
data_length = end_address - start_address
fp = open('E:\path.so', 'wb')

cur = 0
towrite = 0x100000
while cur < data_length:
    if data_length - cur < 0x100000:
        towrite = data_length - cur
    data = idaapi.dbg_read_memory(start_address + cur, towrite)
    fp.write(data)
    cur = cur + towrite

fp.close()
```
执行修复
```$cpp
sofixer -s orig.so -o fix.so -m 0x0 -d 
-s 待修復的so路徑
-o 修復後的so路徑
-m 內存dump的基地址(16位) 0xABC
-d 輸出debug信息
```

# 原理
原理参考下面的文章
TK so修复参考[http://bbs.pediy.com/thread-191649.htm]
* 修复shdr
* 修复phdr
* 修复重定位
