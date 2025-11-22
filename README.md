# Brush-Converter - 笔刷提取
自存，用来提取和转换不同绘画软件的笔刷！
2025年11月23日，彻底解明.abr文件，可以完全解包abr文件的参数表，只需要微调（可以交给ai解决）就能反向打包。只要搞清参数对应关系，其他绘画软件的笔刷转换为ps笔刷使用彻底成为可能。
开源并遵循CC BY-NC 4.0协议，可以使用，但需要注明出处并且严禁商用！
<img width="1595" height="831" alt="image" src="https://github.com/user-attachments/assets/19aa9342-6ccc-46b1-9d42-629c675ca68e" />

Those script can unpack material image files and params from brushes of different software, including .abr(photoshop), .brushset(procreate), .sut(clip studio paint). However it can not pack back yet. Because we still don't know the rules of new version .abr totally, and can not solve digital assets of .layer file in .sut brush. I'm looking for ways. 

Now we can use them in Shell terminal this:
![image](https://github.com/user-attachments/assets/05da91b6-a759-4768-833c-169487428270)
施工中的笔刷转换器，目前可以解包ps的abr笔刷、csp的sut笔刷和procreate的brushset笔刷。
本意是用来把procreate丰富的笔刷资源移植到电脑上，结果在打包ps和csp文件的时候遇到了问题。研究了半天只研究出提取ps和csp笔刷的材质和大部分参数的办法，但是没有办法打包回去。
具体来说：
- 解析了brusheset的材质文件和笔刷参数。网上的土办法提取材质，一般是直接用zip打开，找材质文件，但很多笔刷采用procreate内置材质，笔刷压缩包里是看不到的。所以这个项目补上了这部分。这个项目也解析了了brushset的参数为字典，理论上如果需要可以打包回去。但是procreate是资源最丰富的，它一般当提供资源那个。所以打包没啥意义。
- 不知道新版abr的文件规范，提供了最大帮助的是![这份文档](http://fileformats.archiveteam.org/wiki/Photoshop_brush)，按照它的方式成功提取了材质。很费解的是为什么ps的竞品个个都能解析ps的笔刷，做公益的反而找不到需要的资料。
- csp的笔刷可以用sqlite3解析，其中最大的那个字段提取出来后，以二进制形式写入文件，可以用tar解压，但是用这种方法只能提取出材质的副本（csp用材质的副本作为缩略图）和参数表，csp真正调用的材质文件已经被打包为.layer的数字资产了，目前还没查到要怎么读写。
  
总之先分享了提取用的代码，可以在命令行调用，以提取笔刷中材质！至少目前提取材质是ok了
