so修复相关，so结构研究得不多，勉强够我自己用而已。
使用就是 sofixer -s orig.so -o fix.so -d
如果是从内存中dump出来的，需要加上 -m dumpBase. 可以自动完成重定位的修复。

64位修复没有测试过，应该也没有这个需求吧
原理参考下面的文章
TK so修复参考[http://bbs.pediy.com/thread-191649.htm]
