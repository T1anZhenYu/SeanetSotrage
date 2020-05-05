#ifndef MALLOC_CHUNK_BUF_H
#define MALLOC_CHUNK_BUF_H


uint8_t * get_chunk_buf(void *ptr , uint32_t size);
void free_chunk_buf(void *ptr , uint8_t *chunk ,uint32_t size );


#endif