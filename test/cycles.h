#ifndef SPX_CYCLES_H
#define SPX_CYCLES_H

#ifdef __cplusplus
extern "C"
{
#endif

    void init_cpucycles(void);
    unsigned long long cpucycles(void);

#ifdef __cplusplus
}
#endif

#endif
