#ifndef _MAP_H_
#define _MAP_H_
#include "./debugger.h"
#define MAP_KEY_SIZE_AUTO -1
typedef struct map_item {
	unsigned char km;
	int idx;
	int idx_parent;
	int idx_child[256];
	void *ptr;
} map_item;

struct map {
	int _treesize;
	int count;
	union{
		struct map *root;
		map_item *item;
	} ptr;
};
typedef struct map map;
extern map map_new();
extern void map_put(map *m, unsigned char *, int, void *);
extern void *map_get(map *m, unsigned char *, int);

#endif
