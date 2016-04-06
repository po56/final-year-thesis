

#ifndef DDOSDETECTOR_LINKEDLIST_H
#define DDOSDETECTOR_LINKEDLIST_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct list_node{
    void *data;
    struct list_node *next;
}listnode;

listnode *linkedList_add(listnode *head, void *data);
listnode *linkedList_getByVal(listnode *head, char *val);

#endif //DDOSDETECTOR_LINKEDLIST_H
