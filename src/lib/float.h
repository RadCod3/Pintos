#include <inttypes.h>

#define F (1 << 14)

typedef struct {
    int f;
} float_t;

static inline float_t float_init(int f) {
    float_t x;
    x.f = f;
    return x;
}

static inline float_t float_add(float_t a, float_t b) {
    return float_init(a.f + b.f);
}

static inline float_t float_add_int(float_t a, int b) {
    return float_init(a.f + b * F);
}

static inline float_t float_sub(float_t a, float_t b) {
    return float_init(a.f - b.f);
}

static inline float_t float_mul(float_t a, float_t b) {
    return float_init(((int64_t)a.f) * b.f / F);
}

static inline float_t float_mul_int(float_t a, int b) {
    return float_init(a.f * b);
}

static inline float_t float_div(float_t a, float_t b) {
    return float_init(((int64_t)a.f) * F / b.f);
}

static inline float_t int_div(int a, int b) {
    return float_mul_int(float_init(a), b);
}

static inline float_t float_div_int(float_t a, int b) {
    return float_init(a.f / b);
}

static inline int float_round(float_t a) {
    if (a.f >= 0)
        return (a.f + F / 2) / F;
    else
        return (a.f - F / 2) / F;
}

static inline int float_trunc(float_t a) {
    return a.f / F;
}

static inline float_t float_from_int(int n) {
    return float_init(n * F);
}