# Brush-Converter

Those script can unpack material image files and params from brushes of different software, including .abr(photoshop), .brushset(procreate), .sut(clip studio paint). However it can not pack back yet. Because we still don't know the rules of new version .abr totally, and can not solve digital assets of .layer file in .sut brush. I'm looking for ways. 
Use them in Shell terminal this:
![image](https://github.com/user-attachments/assets/05da91b6-a759-4768-833c-169487428270)
施工中的笔刷转换器，目前可以解包ps的abr笔刷、csp的sut笔刷和procreate的brushset笔刷。
本意是用来把procreate丰富的笔刷资源移植到电脑上，结果在打包ps和csp文件的时候遇到了问题。研究了半天只研究出提取ps和csp笔刷的材质和大部分参数的办法，但是没有办法打包回去。
具体来说，不知道新版abr的文件规范，提供了最大帮助的是这份文档http://fileformats.archiveteam.org/wiki/Photoshop_brush，按照它的方式成功提取了材质。
csp的笔刷可以用sqlite3解析，其中最大的那个字段写入文件后可以用tar解压，但是用这种方法只能提取出材质的副本（csp用材质的副本作为缩略图），csp真正调用的材质文件已经被打包为.layer的数字资产了，目前还没查到要怎么读写。
总之先分享了提取用的代码，可以在命令行调用以提取笔刷中材质。
