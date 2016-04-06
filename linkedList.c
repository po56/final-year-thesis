//
// Created by root on 02/04/16.
//

#include "linkedList.h"

listnode *linkedList_getByVal(listnode *head, char *val){
    listnode *temp = head;
    while (temp != NULL) {
        if (strcmp(temp->data, val) == 0) {
            return temp;
        }
        temp = temp->next;
    }

    return NULL;
}

listnode *linkedList_add(listnode *head, void *data){
    listnode *temp;
    listnode *new = (listnode*) malloc(sizeof(listnode));
    new->data = data;
    new->next = NULL;
    if (head == NULL) {
        head = new;
        temp = head;
    } else {
        temp = head;
        while (temp->next != NULL) {
            temp = temp->next;
        }
        temp->next = new;
    }

    return head;
}




