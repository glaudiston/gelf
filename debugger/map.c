#include "./map.h"

void map_append_km(map *m, int idx, unsigned char c){
	map_item *ptr = (map_item*) ((void*)m->ptr.item + sizeof(map_item) * idx);
	ptr->km |= c;
	if (ptr->idx | ptr->idx_parent){
		map_append_km(m,ptr->idx_parent, ptr->km);
	}
}

int map_new_item(map *m, unsigned char *k, int ks, void * v, int idx_parent){
	map_item *parent = NULL;
	map_item *current = NULL;
	int idx=0;
	if(!m->ptr.item){
		// set space for the root item
		m->ptr.item = realloc(m->ptr.item, sizeof(map_item) * m->_treesize);
		m->ptr.item->idx = 0;
		m->ptr.item->idx_parent = 0;
	}
	parent = (map_item*) (sizeof(map_item) * idx_parent + (void*)m->ptr.item); // S*I+B
	unsigned char c = k[0];
	if (ks > 0 && parent && (parent->km & c) == c && parent->idx_child[c]){
		idx = parent->idx_child[c];
		//printf("(%i,%i)", idx_parent, idx);fflush(stdout);
		int rv = map_new_item(m,&k[1], ks-1, v, idx);
		return rv;
	}
	idx=++m->_treesize;
	size_t rs = sizeof(map_item) * (m->_treesize+1);
	//printf("(0x%02x;%i,%i;ks=%i)", c, idx_parent, idx, ks);fflush(stdout);
	//printf(" \b");fflush(stdout);// No idea why, but if remove this print, realloc will segfault if key is byte 0x01
	void *nptr = realloc(m->ptr.item, rs);
	if ( nptr != NULL ){
		m->ptr.item  = nptr;
	} else {
		//printf("fail to allocate memory"); fflush(stdout);
		exit(1);
	}
	// since we did realloc, the base address can change so let's get the parent again
	parent = (map_item*) (sizeof(map_item) * idx_parent + (void*)m->ptr.item); // S*I+B
	current = (map_item*) (sizeof(map_item) * idx + (void*)m->ptr.item); // S*I+B
	current->idx_parent = idx_parent;
	current->idx = idx;
	//printf("=1=;k[%s]c[%x]=%i\n",k,c,ks);fflush(stdout);
	if (ks>0){
		current->km = c;
		parent->idx_child[c]=idx;
		int rv = map_new_item(m,&k[1], ks -1, v, idx);
		return rv;
	}
	parent = (map_item*) (sizeof(map_item) * idx_parent + (void*)m->ptr.item); // S*I+B
	current = (map_item*) (sizeof(map_item) * idx + (void*)m->ptr.item); // S*I+B
	current->km = 0;
	parent->idx_child[0]=idx;
	m->count++;
	//printf("(%i,%i)[set v=%s]", idx_parent, idx, v);fflush(stdout);
	current->ptr = v;
	//printf("\nptr.root=%p;\n;current=%p\n",m->ptr.item, current);
	parent = (map_item*) (sizeof(map_item) * idx_parent + (void*)m->ptr.root); // S*I+B
	parent->idx_child[c] = idx;
	//printf("(%i[%x]=%i)(%i ptr %x)\n", idx_parent, c, idx, idx, v);
	map_append_km(m,idx, c);
	return idx;
}

int map_get_item_idx(map *m, unsigned char *k, int key_size, int idx){
	unsigned char c = k[0];
	if (key_size==0){
		c=0;
	}
	map_item *item = (map_item*) ((void*)m->ptr.root + sizeof(map_item) * idx);
	//printf("\nmap_get_item_idx: idx:%i, ks=%i\n", idx, key_size);fflush(stdout);
	if (key_size<0){
		if (item->ptr){
			return item->idx;
		}
		return 0;
	}
	//printf("(%i=C=%x;%i)",idx, c,key_size);fflush(stdout);
	if ((item->km & c) != c){
		return 0;
	}
	if (!(item->idx_child[c])){
		//printf("(%i,%i) child not found %x;%p;\n", item->idx_parent, item->idx, c, item->ptr);fflush(stdout);
		return 0;
	}
	return map_get_item_idx(m,&k[1], key_size-1, item->idx_child[c]);
}

void map_put(map *m, unsigned char *key, int key_size, void *value){
	if (key_size == MAP_KEY_SIZE_AUTO){
		key_size = strlen((char*)key);
	}
	//printf("\nadding: key[%x,%s=%x](size: %i):", (unsigned char)key[0], key, value, key_size);fflush(stdout);
	if (!m->ptr.item){
		int rv = map_new_item(m,key, key_size, value, 0);
		return;
	}
	int idx = map_get_item_idx(m,key, key_size, 0);
	map_item *item = (map_item*) ((void*)m->ptr.item + sizeof(map_item) * idx);
	if (item->ptr){
		//printf("found %s\n",key);fflush(stdout);
		// found item. increment and replace;
		item->ptr = value;
		return;
	}
	map_new_item(m,key, key_size, value, 0);
}
void *map_get(map *m, unsigned char *key, int key_size){
	if (key_size == MAP_KEY_SIZE_AUTO){
		key_size = strlen((char*)key);
	}
	//printf("\nget %s(%x; %i)",key,key[0], key_size);
	int idx = map_get_item_idx(m, key, key_size, 0);
	map_item *item = (map_item*) ((void*)m->ptr.item + sizeof(map_item) * idx);
	return item? item->ptr: NULL;
}

map map_new(){
	map m = {
		._treesize = 0,
		.count = 0,
		.ptr.root = NULL,
	};
	return m;
}

