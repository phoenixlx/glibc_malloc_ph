## 源代码中释放free过程的关键路径

### 最外层的__lib_free(mem)：
```C
if 给出的mem参数为0        //对于free(0)的处理
    return;

p = mem2chunk(mem);  //根据mem指针得到chunk指针

#if HAVE_MMAP开启

    if chunk_is_mmap(p)     //检查mmap标志位
        if 检查是否需要调整brk和mmap的值
            调整之
        调用munmap_chunk()； //这个函数内调用munmap()系统调用释放chunk.
#endif

ar_ptr = arean_for_chunk(p);  //根据chunk指针获得所在分配区arena的指针

#if ATOMIC_FASTBINS开启
    不需要加锁，直接调用_int_free(ar_ptr,p,0)主函数
    
#else ATOMIC_FASTBIN未开启
    mutex_lock(&ar_ptr->mutex);   //需要对arena加锁
    调用释放主函数_int_free(&ar_ptr,p)
    mutex_unlock(&ar_ptr->mutex);   //释放完对arena解锁
    
```

---

注意，这里有两个_int_free函数，函数原型分别为：  
> _int_free(mstate av, mchunkptr p, int have_lock)  // 有ATOMIC_FASTBINS优化    
> _int_free(mstate av, mchunkprt p) //无


第一个参数av是内存块所属的arena，第二个p是内存指针，第三个可选项

### 核心释放函数_int_free
malloc.c#4759
```C
参数声明：
size - 待释放chunk大小；  
fb - fast bin指针；
nextchunk - 下一个chunk指针
nextsize - 下一个chunk的大小
nextinuse - 下一个chunk的inuse位
prevsize - 前一个chunk的大小
bck,fwd - 链表操作临时变量

size = chunksize(p);    //获取需要释放的chunk大小

//检查开始
检查 p地址溢出和对齐
    ”free():invalid pointer“ 报错无效指针
检查chunk的大小是否比MINSIZE小
    "free():invalid size" 报错无效大小
check_inuse_chunk(av,p);  //检查chunk的inuse位
//检查结束

if size < get_max_fast() //如果size小于fastbin的最大大小
    if 下一个chunk的大小小于等于2*SIZE_SZ或者大于分配区所分配的内存总量
        “free():invalid next size”报错
    
    set_fastchunks(av); //设置当前分配区的 fast bin flag
    unsigned int idx = fastbin_index(size); //得到待释放chunk大小对应的索引
    fb = &fastbin(av,idx)； //得到指向对应fast bin的指针
    
    #ifdef ATOMIC_FASTBINS
        检查是否double free
            报错
        使用lock-free技术实现对fast bin的单向链表插入操作。
    
    #else 没有FASTBINS优化
        检查是否 double free
            报错
            goto errout
        检查表头不为NULL，并且表头所属fast bin与当前要释放的chunk属于同一个fast bin
            报错invalid fastbin entry
            goto errout
            
        p->fd = *fb;    //插在链表头部，因为取也在头部取，所以实际是一个LIFO链表
        *fb =p;         
    #endif
//这里处理完了所有大小处于fast bin之间的chunk

//开始合并其他非mmap的chunk
else if (!chunk_is_mmaped(p))   //chunk并不是mmap来的，而是在heap区
    #ifdef ATOMIC_FASTBINS
        if 没有获得锁
            获取锁
            locked =1  标记已锁
    #endif
    
    nextchunk = chunk_at_offset(p,size);    //获取下一个相邻的chunk指针
    
    检查当前free的chunk是否为 top chunk
        goto errout
    检查下一个相邻的chunk是否超出了本arena的边界
        goto errout
    检查下一个相邻chunk的size中标志位是否标记当前chunk为inuse状态
        goto errout
        
    nextsize = chunksize(nextchunk);   //计算下一个相邻的chunk的大小
    检查该大小是否有效
        goto errout
    
    //向前合并
    if 前一个chunk空闲
        unlink(p,bck,fwd);   //合并，计算合并后大小，然后从空闲链表中删除
    
    if nextchunk并不是top chunk
        得到其inuse状态
        
        //向后合并
        if (!inuse)   下一个chunk也处于空闲
            unlink（nextchunk,bak,fwd）;  //合并，增加size并从空闲链表中删除
        else
            清除当前chunk的inuse状态
        
        //将合并后chunk放入unsorted bin的双向循环链表，所有释放的chunk不会被立即放入到常规bins中，直到它们在unsorted中被给了一次被分配的机会
        bck = unsorted_chunks(av);  //用临时指针变量获得unsorted_bin的头
        fwd = bck->fd;  //
        
        p->fd = fwd;
        p->bk = bck;
        if (!in_small_range(size))   //如果处于large bin
            将size链表的指针置空，因为在unsorted bin中这两个没用
        bck ->fd = p;
        fwd ->bk = p;    //共计4次指针操作，插入完成
        
        set_head(p,size)   //标记前一个chunk为inuse状态
        set_foot(p,size)  //这里的foot实际上是下一个chunk的heah中的per_size
        check_free_chunk(av,p)  检查
    //这里处理完了当前释放的chunk不与top chunk相邻的情况
    
    else    //如果当前释放的chunk正好与top chunk相邻
        合并入top chunk
        av->top = p;
        check_chunk(av,p)

    //收缩堆操作，看能不能收缩
    
    if 合并后的size大于64KB
        if fast bins中有空闲chunk
            malloc_conslidate(av);  //合并fast bin中的chunk并放入unsorted bin
        if 当前分配区是主分配区
            if top chunk大于heap的收缩阈值
                systrim()       //收缩
        else //非主分配区
            heap_trim()    //收缩
    
//这里处理完了所有不是来自mmap的内存区
else
    munmap_chunk()
    
//全部结束
```

#### 收缩堆systrim()——主分配区的搜索
本质就是sysmalloc的逆过程。如果在堆中高地址（指top chunk）有很多未使用的空间，其归还内存给操作系统（通过给sbrk()设置负参数）

当top空间达到阈值时由free调用，也可以由malloc_trim调用

如果确实释放了内存，返回1；否则0

#### heap_trim()——子分配区的搜索
根据sub_heap的top chunk大小调用shrink_heap()函数收缩sub_heap

#### munmap_chunk() 
获取当前free的chunk大小；
检查对齐；
更新mmap统计信息；
调用munmap()系统调用释放内存

### malloc_consolidate() ——将fast bins中的chunk合并并放入unsorted bin
>  值得注意的是，**其他类型的chunk的合并是在free路径中完成的**
>  先向前合并，再向后合并，再看能不能合并到top_chunk中

```C
    //如果max_fast为0，意味着分配区还没有初始化
    if max_fast不为0
        clean_fastchunks(av);   //清除fast bin标志位
    
        unsorted_bin = unsorted_chunks(av); //获取unsorted bin的指针
        maxfb = &fastbin(av,NFASTBINS -1)； //fast bin中最大的一个单链表
        fb = &fastbin(av,0);  //第一个fast bin给fb
        p = *fb;
        
        do
            获取当前fast bin中空闲chunk的单链表的头指针给p
        
            if p非空
                赋p为0，即删除了该fast bin中的空闲chunk链表
                do
                    检查inuse位
                    nextp = p-> fd; 当前chunk链表下一个chunk赋给nextp
                
                    获取当前chunk的size并除去size中的PREV_INUSE和NON_MAIN_ARENA标志
                    获取下一个chunk及其大小（nextchunk和nextsize）
                
                    if  当前chunk的前一个空闲
                        与前一个chunk合并
                        unlink;  //从fast bin中摘除chunk
                
                    if 下一个chunk并不是top chunk
                        获取其INUSE状态位
                        if 状态位为0，表示下一个chunk处于空闲状态
                            合并
                            unlink; //将下一个chunk删除
                        else //状态位为1，表示下一个chunk处于inuse状态
                            清除inuse状态
                    
                        first_unsorted = unorted_bin ->fd;
                        unsorted_bin ->fd =p;
                        first_unorted ->bk = p;  //将合并后的chunk加入unsorted bin的双向循环链表，还少了两个first_unosrted的指针操作，在后面
                    
                        if 合并后的size不属于small bin
                            将无效的chunk_size指针字段设为NULL
                            
                        设置合并后的chunk_size
                        完成unsorted_bin的插入操作，放在第一个
                        设置foot，也就是下一个chunk的pre_size域为当前chunk大小size
                    //这里处理完了下一个chunk非top chunk的情况    
                        
                    else 下一个chunk是top chunk
                        将当前chunk合并入top_chunk
                    
                while  (nextp !=0 ) //直到该大小单链表内的所有chunk被遍历完
        
        while  (fb++ !=maxfb) //直到遍历完所有fast bin
    else //max_fast为0，表示系统还没有初始化
        malloc_init_state(av); //就初始化之
        check_malloc_state(av);
        
//全部结束
```

---
## 源代码中分配malloc过程的关键路径

### 最外层的__lib_malloc(mem)
malloc.c#3614  函数参数仅一个，就是希望分配的大小
> 看下面的的过程可以知道，分配器会努力尝试在多个分配区arena执行分配主函数，尽力满足分配请求

```C
参数声明：
ar_ptr - 分配区arena指针
victim - 为将要被分配选择的块（将要'牺牲'的块）

首先检查是否存在内存分配的 hook 函数，如果存在，调用 hook 函数，并返回， hook函数主要用于进程在创建新线程过程中分配内存，或者支持用户提供的内存分配函数

arena_lookup(ar_ptr);  //获取分配区指针
arena_lock()；         //加锁  （！注意这里对应的解锁在最后！）
if 获取分配区失败
    return 0;

victim = _int_malloc(ar_ptr,bytes);     //调用核心分配函数_int_malloc()分配内存

if (!victim)   //分配失败，当系统OOM的时候是有可能的
//总体解决方案就是换个分配区再试试

    if ar_ptr不是主分配区
        mutex_unlock    解锁
        ar_ptr = &main_area;
        mutex_lock     加锁
        victim = _int_malloc(ar_ptr,bytes);   //再试一次
        mutex_unlock   解锁
    
    else 已经是主分配区了
        ar_ptr = arena_get2(ar_prt->next?ar_ptr : 0, bytes);  //如果有非主分配区，就赋给ar_ptr
        解锁
        if ar_ptr  //如果有非主分配区
            victim = _int_malloc();    //再试一次
            解锁
    
//完成了分配失败的处理
else    //分配成功
    mutex_unlock()；   解锁

返回 victim

```
### 核心分配函数_int_malloc
malloc.c#4247  
int_malloc(mstate av, size_t bytes)    
两个参数分别是arena指针和希望分配的大小，参数来自上层的public_malloc()

``` C
参数声明：
nb - 实际申请的chunk大小
idx - bin链表索引
bin - bin指针

victim - 待分配的chunk
size - 其大小
victim - 其对应的bin索引

remainder - 分割后剩下的chunk
remainder_size - 其大小

block
bit
map -用于bin位图

bck,fwd - 链表操作临时变量

*errstr - 不同阶段要打印的出错信息


//将需要的内存大小（传入参数）转换成（对齐）需要分配的chunk大小 nb。
check_request2sizes(bytes,nb);   

//首先处理小请求， 分配fast bin chunk
if (nb < get_max_fast())
    idx = fastbin_index(nb);  //获取fastbin中nb对应的bin链表索引
    fb = &fastbin(av, idx);     //获得对应bin链表的头指针

    victim = *fb;   
    if (victim != 0)   //bin链表非空
        if 检查所选的victim是否跟chunk处于同一index的bin内
            给errstr赋值并通过errout标签 输出错误信息
errout:     
            malloc_printerr()； //malloc内部使用的打印错误信息函数 
            return NULL；
    *fb = victim ->fd;  //fd指向下一个，相当于将bin链表的第一个元素取出
    
    check_remalloced_chunk()
    void *p = chunk2mem(victim);    //chunk转换成mem指针
    
    返回指针p；  //分配成功

//这里结束了对fast bin chunk的处理


//然后处理small bin chunk
if (in_small_range(nb))
    idx = smallbin_index(nb);   //获取small bin中nb对应的bin链表索引
    bin = bin_at(av,idx);       //获得对应bin链表的头指针
    
    if ((victim = last(bin))!=bin)   //将bin链表最后一个chunk赋给victim，如果正好就是表头的话，表示链表为空
        if victim == 0   //small bin还没有初始化为双向循环链表
            malloc_consolidate();    //合并fast bins中的chunk   ！！这里为啥要合并？！
        
        else  //bin已经初始化
            bck = victim ->bk;
            if 检查bck的fd指针是否指向victim
                给errstr赋值
                跳转到上面的 errout标签并退出
            
            设置victim的inuse标志，该标志处于下一个相邻chunk的size字段的最后一个bit
            bin ->bk = bck;
            bck ->fd = bin;  //到这里完成了最后一个chunk的取出
            
            if 当前的arena不是main arena
                将victim的size字段中表示非主分配区的标志bit清零
            检查
            void *p = chunk2mem(victim);    //chunk转换成mem指针
            
            返回指针p;    //分配成功
    
//这里结束了对small bin chunk的部分处理，也就是分配成功的情况！
//！！但是！！当对应的small bin中没有空闲chunk或者对应的small bin还没有初始化，并没有得到chunk的情况并没有处理，需要后面的步骤


//然后处理large bin chunk以及前面未分配成功的情况

else   //不在small bin的范围内，那肯定是large bin
    idx = largebin_index(nb);
    if 有fastbin
        malloc_consolidate(av)；    //！！又合并？！！


for (;;)    //死循环，但注意，在不同的地方是有不同退出接口的，比如返回指针和出错信息等
    iters =0;  这个是迭代计数器，当迭代了10000次时会退出。
    
    while ((victim = unsorted_chunks(av)->bk)!=unsorted_chunks(av))     //从最后一个chunk开始，反向遍历unsorted bin双向循环链表直到又绕了一圈回到头结点
    
        bck = victim->bk;
        if 检查：1、chunk大小不能小于2*SIZE_SZ；2、也不能超过分配区总的分配量
            malloc_printerr();  //输出错误信息
        chunk2mem(victim);      //直接转换成mem指针？ 但是并没有赋给P啊？
        size = chunksize(victim);  //得到相应的大小
        
        //接下来是尝试从unsorted bin分配small chunk
        
        if //再次判断是不是需要分配一个small chunk && unsorted bin中只有一个chunk && 这个chunk是last_remainder && 这个chunk的大小比请求的大小nb要大
        
            //就分割remainder
            remainder_size = size -nb;
            remainder = chunk_at_offset(victim,nb);
            分割后的remainder再放入unsorted bin
        
            if remainder分割后剩下的大小不属于small bin
                不需要指向其他size的bin指针，置为NULL（这两个指针只有large bin链表中才有）
        
            set_head();     //设置分配出去的chunk的信息，包括size、inuse、主分配器等
            设置remainder的head和foot信息
        
            检查
            void *p = chunk2mem(victim);
        
            返回指针p；     //分配成功
        //这里完成了在unsorted bin中remainder chunk分配small chunk的过程
        
        //取出unsorted bin中尾部的这个chunk
        unsorted_chunks(av) ->bk = bck;
        bck->fd = unsorted_chunks(av);
        
        if size==nb   //如果victim跟请求的大小刚刚好
            设置inuse标志位
            if av不是主分配区
                设置非主分配区标志位
            检查
            void *p = chunk2mem(victim);
            
            返回指针p;  //分配成功
        
        //将这个不满足要求的victim放入small bin和large bin中
        if in_smallbin_range(size)   //如果victim的大小属于small bin范围（16,512）
            victim_index = smallbin_index(size);    //获得victim所属的small bin的index
            bck = bin_at(av, victim_index);     //将chunk插入相应索引bin链表的第一个
            fwd = bck ->fd;
        else
            victim_index = largebin_index(size);
            bck = bin_at(av,victim_index);  //同上，插入large bin
            fwd = bck->fd;
            
            if (fwd! = bck)     //意味着large bin有其他空闲chunk，因为large bin中的空闲chunk是按照从大到小顺序排序的，需要将当前从unsorted bin中取出的chunk插入到large bin中合适的位置。
                
                将victim的inuse标志位置1，相当于size++
                assert检查
                if victim的大小比large bin链表中最后一个还小（先处理特殊情况）
                    插入到最后
                else    //否则处理一般情况
                    while   //需要正向遍历链表，直到有一个chunk的大小大于等于victim
                        fwd = fwd->fd_nextsize;
                    if 找到了相同大小的chunk
                        插在这个chunk后面
                    else  //找到的chunk比size大
                        以victim作为该chunk size的代表加入chunk size链表
                    
                    bck = fwd->bk;
            //这里处理完了victim插入到large bin中
            
            else   //large bin没有其他空闲chunk
                victim ->fd_nextsize = victim->bk_nextsize = victim;    //将当前chunk作为第一个
        
        //这里处理完了将victim放入small bin和large bin中的流程
        
        mark_bin(av,victim_index);    //在large bin相应bitmap的相应bit置位
        
        victim->bk = bck;       //接下来四行代码是真正在bin链表中插入victim的操作
        victim->fd = fwd;       //small bin和large bin都要执行这段代码
        fwd->bk = victim;
        bck->fd = victim;
        
        //这里其实是避免长时间处理unsorted bin而影响内存分配的效率
        #define MAX_ITERS 10000   
        if （++iters >= MAX_ITERS） 
            break;  //跳出while循环，但仍然在for(;;)里
    
    //while循环结束    
    
    
    //当unsorted bin中空闲chunk加入到相应的small bins和large bins后，使用最佳适配法来分配large bin chunk    
    
    if ！in_smallbin_range(nb)
        bin = bin_at(av,idx);
    
        if large bin链表非空 &&该来表最大chunk的大小大于所需的nb
            victim = victim->bk_nextsize;
            while //反向遍历，直到找到第一个大于等于所需nb的victim
            
            if 找到的chunk不是bin的最后一个，其其后有等大小的chunk待分配
                victim = victim->fd;   //就分配它后面那个，这样可以避免对chunk_size链表的操作，因为每个新的size都会在chunk_size链表中
            
            remainder_size = size - nb;     //计算将victim切分后剩余大小
            unlink(victim,bck,fwd);   //从large bin链表中取出
            
            if remainder_size太小   //则不分割，将整个victim分配出去
                设置victim的inuse位
                if av不是主分配区
                    标记victim的size字段主分配区标志位
            
            //将victim分割，剩下的放入unsorted bin中
            else
                remainder = chunk_at_offset(victim,nb);
                bck = unsorted_chunks(av);
                fwd = bck ->fd;
                if 检查unsorted的fwd和bck是否有问题
                    给errstr赋值
                    跳转到之前的 errout标签并退出
                
                remainder->bk = bck;    //以下链表操作将remainder插入unsorted bin
                remainder->fd = fwd;
                bck->fd = remainder;
                fwd->bk = remainder;
                
                if remainder_size属于laege bin
                    将size指针置位NULL，unsorted bin里用不到这个指针信息，因为无序
                
                设置victim的head和标志位等
                设置remainder的head和foot
            //分割remainder并插入unsorted bin完成
            
            检查
            void *p = chunk2mem(victim);
            
            返回指针p； //分配结束
    
    //此处结束了large bin的成功分配
    
    //如果上面的方式从合适的small bin或large bin中都没有分配到需要的chunk，则查看比当前bin的index的大的small bin或large bin是否有空闲chunk可用来分配所需的chunk。
    
    ++idx； //下一个large bin里的chunk一定比当前large bin的要大
    bin = bin_at(av,idx);
    block = idx2block(idx);
    map = av->binmap[block];    //binmap管理了bin链表内是否有空闲chunk存在。binmap按block管理，每个block为一个int，共32个bit，可以表示32个bin中是否存在空闲chunk。使用binmap可以加快查找
    bit = idx2bit(idx)；   //idx2bit()将指定的位设置为1
    
    for(;;)     //第二个死循环
        if bit > map ||bit==0   //bit大于map意味着map为0，也就是该block对应的所有bins链表都为空
            do{
                if block自增然后与BINMAPSIZE比较，大于的话
                    goto use_top;      //说明没找到合适的bin，跳去top chunk处理
            }
            while(map = av->binmap[block]==0);  //一个block一个blick的遍历
            
            //找到了  如果这个bin中有空闲chunk，则该chunk的大小一定满足要求
            bin = bin_at();   //设置bin指向第一个bit对应的bin
            bit = 1;    //表示该block中bit1对应的bin
        //endif
        while (bit&map)==0  //block内循环，知道找到一个不为0的bin
            bin = next_bin(bin);
            bit <<= 1;
        
        victim = last(bin);     //将找到的bin链表的最后一个chunk赋值给victim
        if （victim == bin）  //表示位图信息有误
            更新
            bin = next_bin(bin);    //找下一个bin
            bit <<= 1;
        else    //位图信息正确
            size = chunksize(victim);  //获得该chunk的大小
            assert size一定大于nb
            
            //分割victim    ！！到这个地方跟前面在large bin里分割的差不多，但对remainder的处理略有区别！！
            remainder_size = size - nb;   //计算切割后大小
            unlink();    //从bin的链表中取出
        
            if remainder_size太小
                不分割
                if av不是主分配区
                    设置victim的非主分配区标志位
            
            //将victim分割，剩下的放入unsorted bin中
            else
                remainder = chunk_at_offset(victim,nb);
                bck = unsorted_chunks(av);
                fwd = bck ->fd;
                if 检查unsorted的fwd和bck是否有问题
                    给errstr赋值
                    跳转到之前的 errout标签并退出
                
                remainder->bk = bck;    //以下链表操作将remainder插入unsorted bin
                remainder->fd = fwd;
                bck->fd = remainder;
                fwd->bk = remainder;
                
                if nb的大小是small bin      //！这里是跟之前不同的地方！
                    av ->last_remainder = remainder;  
                    //将剩下部分设置成分配区的last remainder。所谓的last_remainder就是最近一次由于小请求导致的分割而产生的空闲chunk。
                    
                if remainder_size属于laege bin
                    将size指针置位NULL，unsorted bin里用不到这个指针信息，因为无序
                
                设置victim的head和标志位等
                设置remainder的head和foot
            //分割victim并插入unsorted bin完成
            
            检查
            void *p = chunk2mem(victim);
            
            返回指针p； //分配结束
            
    //第二个for循环结束
    
    //如果从所有的bins中都没有获得所需的chunk，可能的情况为bins中没有空闲chunk或者所需要的chunk大小非常大，下一步将尝试从top chunk中分配所需chunk。

use_top:
    victim = av->top;       //将当前分配区的top chunk赋值给victim
    size = chunksize(victim);   //获得victim的大小
    
    if top chunk比nb+MINISIZE 大
        remainder_size = size -nb;
        remainder = chunk_at_offset(victim,nb);
        av ->top = remainder;   //remainder并不放入unsorted bin而是继续作为top chunk
        
        设置victim的head和标志位等
        设置remainder的head   //这里没有设置foot，因为remainder是继续作为top chunk
        
        检查
        void *p = chunk2mem(victim);
            
        返回指针p； //分配结束
        
#ifdef ATOMIC_FASTBINS
    //top chunk不够大
    else if (have_fastchunks(av))   //当前arena有fast chunk
        malloc_consolidate(av);    //再一次合并！
        
        if nb属于small chunk
            idx = smallbin_index(nb);
        else //nb属于large chunk
            idx = largebin_index(nb);

#else   //没有开启ATOMIC_FASTBINS优化
    else if(have_fastchunks(av))
        malloc_consolidate(av);
        idx = smallbin_index(nb);
        //如果fast bins有空闲chunk存在，只有一种可能：所需的chunk属于small chunk，但通过前面的步骤都没有分配到所需的small bin chunk，由于分配small bin chunk时在前面的步骤中都不会调用malloc_consolidate()函数将fast bins中的空闲chunk合并加入到unsorted bin中。所以这里需要重新设置当前bin的idx，并跳转到最外层的循环，尝试重新分配。

#endif
    
    //到这里，说明分配器内合并后也无法满足请求，只能向OS要了
    else
        void *p = sYSMALLOc(nb,av);  //sysmalloc并不是系统调用，而是封装的函数，参数为所请求的chunk的大小
        
        返回指针p； //分配结束
        
//最外层for循环结束
//_int_malloc结束
```

### 跟操作系统申请内存的辅助分配函数sysmalloc()
malloc.c#2964  
> sYSMALLOc(INTERNAL_SIZE_T nb,mstate av)    
sYSMALLOc()函数直接向系统申请内存用于分配所需的chunk

```C
参数声明：
old_top - 用来存储当前av->top的值
old_top - top chunk的大小
old_end - top chunk的结束地址

size - 用于第一次MORECORE 或者 mmap调用的参数
brk - MORECORE的返回值

correction - 用于第二次MORECORE的参数
snd_brk - 第二次的返回值

front_misalign - 新申请空间前部由于对齐而无法使用的大小
end_misalign -   。。。。。后部。。。

p - 返回的mem指针
remainder - 分割剩下的
remainder_size - 其大小

sum - 更新状态
pagemask - 页面掩码
tried_mmap = false  使用mmap的标记

//这部分的细节暂且不提，以后如果需要改这一块再深究

主要就是尝试MORECORE和mmap系统调用，MORECORE就是sbrk。




```
