#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "myhashMap.h"

// //hashnode struct
// typedef struct hashEntry{
//     char* key;
//     char* value;
//     struct hashEntry* next;
// }entry;

// //typedef struct hashEntry entry;
// typedef struct hashTable{
//      entry bucket[BUCKETCOUNT];  //16 bucketcount
// }table;

// //typedef struct hashTable table;

//initHashtable
void initHashTable(table* t){
    int i;
    if (t == NULL)return;
    for (i = 0; i < BUCKETCOUNT; ++i) {
        t->bucket[i].key = NULL;
        t->bucket[i].value = NULL;
        t->bucket[i].next = NULL;
    }
}

void freeHashTable(table* t){
    int i;
    entry* e,*ep;
    if (t == NULL)return;
    for (i = 0; i < BUCKETCOUNT; ++i){
        e = &(t->bucket[i]);
        while (e->next != NULL){
            ep = e->next;
            e->next = ep->next;
            free(ep->key);
            free(ep->value);
            free(ep);
        }
    }
}

//散列算法 
int keyToIndex(const char* key){
    int index, len, i;
    if (key == NULL)return -1;

    len = strlen(key);
    index = (int)key[0];
    for (i = 1; i<len; ++i) {
        index *= 1103515245 + (int)key[i];
    }
    index >>= 27;
    index &= (BUCKETCOUNT-1);
    return index;
}

//在堆上分配足以保存str的内存
//并拷贝str内容到新分配位置
char* strDup(const char* str)
{
    int len;
    char* ret;
    if (str == NULL)return NULL;

    len = strlen(str);
    ret = (char*)malloc(len + 1);
    if (ret != NULL) {
        memcpy(ret , str , len);
        ret[len] = '\0';
    }
    return ret;
}

//向哈希表中插入数据
int insertEntry(table* t , const char* key , const char* value)
{
    int index , vlen1 , vlen2;
    entry* e , *ep;

    if (t == NULL || key == NULL || value == NULL) {
        return -1;
    }

    index = keyToIndex(key);
    if (t->bucket[index].key == NULL) {
        t->bucket[index].key = strDup(key);
        t->bucket[index].value = strDup(value);
    }
    else {
        e = ep = &(t->bucket[index]);
        while (e != NULL) { //先从已有的找
            if (strcmp(e->key , key) == 0) {
                //找到key所在，替换值
                vlen1 = strlen(value);
                vlen2 = strlen(e->value);
                if (vlen1 > vlen2) {
                    free(e->value);
                    e->value = (char*)malloc(vlen1 + 1);
                }
                memcpy(e->value , value , vlen1 + 1);
                return index;   //插入完成了
            }
            ep = e;
            e = e->next;
        } // end while(e...

        //没有在当前桶中找到
        //创建条目加入
        e = (entry*)malloc(sizeof (entry));
        e->key = strDup(key);
        e->value = strDup(value);
        e->next = NULL;
        ep->next = e;
    }
    return index;
}

//在哈希表中查找key对应的value
//找到了返回value的地址，没找到返回NULL
const char* findValueByKey(const table* t , const char* key)
{
    int index;
    const entry* e;
    if (t == NULL || key == NULL) {
        return NULL;
    }
    index = keyToIndex(key);
    e = &(t->bucket[index]);
    if (e->key == NULL) return NULL;//这个桶还没有元素
    while (e != NULL) {
        if (0 == strcmp(key , e->key)) {
            return e->value;    //找到了，返回值
        }
        e = e->next;
    }
    return NULL;
}

//在哈希表中查找key对应的entry
//找到了返回entry，并将其从哈希表中移除
//没找到返回NULL
entry* removeEntry(table* t , char* key)
{
    int index;
    entry* e,*ep;   //查找的时候，把ep作为返回值
    if (t == NULL || key == NULL) {
        return NULL;
    }
    index = keyToIndex(key);
    e = &(t->bucket[index]);
    while (e != NULL) {
        if (0 == strcmp(key , e->key)) {
            //如果是桶的第一个
            if (e == &(t->bucket[index])) {
                //如果这个桶有两个或以上元素
                //交换第一个和第二个，然后移除第二个
                ep = e->next;
                if (ep != NULL) {
                    entry tmp = *e; //做浅拷贝交换
                    *e = *ep;//相当于链表的头节点已经移除
                    *ep = tmp;  //这就是移除下来的链表头节点
                    ep->next = NULL;
                }
                else {//这个桶只有第一个元素
                    ep = (entry*)malloc(sizeof(entry));
                    *ep = *e;
                    e->key = e->value = NULL;
                    e->next = NULL;
                }
            }
            else {
                //如果不是桶的第一个元素
                //找到它的前一个(这是前面设计不佳导致的多余操作)
                ep = &(t->bucket[index]);
                while (ep->next != e)ep = ep->next;
                //将e从中拿出来
                ep->next = e->next;
                e->next = NULL;
                ep = e;
            }
            return ep;
        }// end if(strcmp...
        e = e->next;
    }
    return NULL;
}

void printTable(table* t)
{
    int i;
    entry* e;
    if (t == NULL)return;
    for (i = 0; i<BUCKETCOUNT; ++i) {
        printf("\nbucket[%d]:\n" , i);
        e = &(t->bucket[i]);
        while (e->key != NULL) {
            printf("\t%s\t=\t%s\n" , e->key , e->value);
            if (e->next == NULL)break;
            e = e->next;
        }
    }
}

int main()
{
    table t;
    initHashTable(&t);

    insertEntry(&t , "电脑型号" , "华硕 X550JK 笔记本电脑");
    insertEntry(&t , "操作系统" , "Windows 8.1 64位 (DirectX 11)");
    insertEntry(&t , "处理器" , "英特尔 Core i7 - 4710HQ @ 2.50GHz 四核");
    insertEntry(&t , "主板" , "华硕 X550JK(英特尔 Haswell)");
    insertEntry(&t , "内存" , "4 GB(Hynix / Hyundai)");
    insertEntry(&t , "主硬盘" , "日立 HGST HTS541010A9E680(1 TB / 5400 转 / 分)");
    insertEntry(&t , "显卡" , "NVIDIA GeForce GTX 850M       (2 GB / 华硕)");
    insertEntry(&t , "显示器" , "奇美 CMN15C4(15.3 英寸)");
    insertEntry(&t , "光驱" , "松下 DVD - RAM UJ8E2 S DVD刻录机");
    insertEntry(&t , "声卡" , "Conexant SmartAudio HD @ 英特尔 Lynx Point 高保真音频");
    insertEntry(&t , "网卡" , "瑞昱 RTL8168 / 8111 / 8112 Gigabit Ethernet Controller / 华硕");
    insertEntry(&t , "主板型号" , "华硕 X550JK");
    insertEntry(&t , "芯片组" , "英特尔 Haswell");
    insertEntry(&t , "BIOS" , "X550JK.301");
    insertEntry(&t , "制造日期" , "06 / 26 / 2014");
    insertEntry(&t , "主人" , "就是我");
    insertEntry(&t , "价格" , "六十张红色毛主席");
    insertEntry(&t , "主硬盘" , "换了个120G的固态");
    //insertEntry(&t , "11","10");

	entry* e = removeEntry(&t , "主板型号");

    if (e != NULL) {
         puts("找到后要释放");
         free(e->key);
         free(e->value);
        free(e);
         e = NULL;
     }

    printTable(&t);

	int i; 
    const char* keys[] = { "显示器" , "主人","没有" , "处理器" };
    for (i = 0; i < 4; i++) {
        const char* value = findValueByKey(&t , keys[i]);
        if (value != NULL) {
            printf("find %s\t=\t%s\n" ,keys[i], value);
        }
        else {
            printf("not found %s\n",keys[i]);
        }
    }


    freeHashTable(&t);
    getchar();
    return 0;
}
