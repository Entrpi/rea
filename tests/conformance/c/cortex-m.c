/* Freestanding, source-owned M-profile fixture. Never executed by REA. */
typedef unsigned int rea_u32;

volatile rea_u32 rea_cm_ticks;
volatile rea_u32 rea_cm_calls;
volatile float rea_cm_floats[2];
volatile double rea_cm_doubles[2];
volatile float rea_cm_float_out;
volatile double rea_cm_double_out;

/*
 * Floating-point arguments and results pass in r0-r3 under the base
 * procedure-call standard and in s0-s15 and d0-d7 under AAPCS-VFP. The
 * counter keeps each call: without a side effect, the optimizer replaces a
 * call to a function that returns an argument with that argument.
 */
__attribute__((noinline)) float rea_cm_fadd(float a, float b)
{
    return a + b;
}

__attribute__((noinline)) float rea_cm_fpick(float a, float b)
{
    (void)a;
    rea_cm_calls += 1u;
    return b;
}

__attribute__((noinline)) double rea_cm_dpick(double a, double b)
{
    (void)a;
    rea_cm_calls += 1u;
    return b;
}

#if defined(__ARM_ARCH_PROFILE) && __ARM_ARCH_PROFILE == 'M'
/* An M-profile system register, which the A-profile decoder names otherwise. */
__attribute__((noinline)) rea_u32 rea_cm_primask(void)
{
    rea_u32 value;
    __asm volatile("mrs %0, primask" : "=r"(value));
    return value;
}
#endif

#if defined(__ARM_ARCH_8M_MAIN__) || defined(__ARM_ARCH_8_1M_MAIN__)
/* The ARMv8-M stack limit, which the ARMv7 decoder lacks. */
__attribute__((noinline)) void rea_cm_msplim(rea_u32 limit)
{
    __asm volatile("msr msplim, %0" : : "r"(limit));
}
#endif

#if defined(__ARM_ARCH_8_1M_MAIN__)
volatile rea_u32 rea_cm_values[4];

/* A loop whose count is unknown: WLS/LE, which only ARMv8.1-M has. */
__attribute__((noinline)) rea_u32 rea_cm_sum(const volatile rea_u32 *values,
                                             rea_u32 count)
{
    rea_u32 sum = 0u;
    for (rea_u32 i = 0u; i < count; i++)
        sum += values[i];
    return sum;
}
#endif

/* Reached only through the vector table. */
void SysTick_Handler(void)
{
    rea_cm_ticks += 3u;
}

void Reset_Handler(void)
{
    rea_cm_float_out = rea_cm_fadd(rea_cm_floats[0], rea_cm_floats[1]) +
                       rea_cm_fpick(rea_cm_floats[0], rea_cm_floats[1]);
    rea_cm_double_out = rea_cm_dpick(rea_cm_doubles[0], rea_cm_doubles[1]);
#if defined(__ARM_ARCH_PROFILE) && __ARM_ARCH_PROFILE == 'M'
    rea_cm_ticks = rea_cm_primask();
#endif
#if defined(__ARM_ARCH_8M_MAIN__) || defined(__ARM_ARCH_8_1M_MAIN__)
    rea_cm_msplim(0x20000000u);
#endif
#if defined(__ARM_ARCH_8_1M_MAIN__)
    rea_cm_ticks = rea_cm_sum(rea_cm_values, rea_cm_calls);
#endif
    for (;;) {
    }
}
