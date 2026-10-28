/* Source-owned freestanding call0 analysis fixture. Never execute this target. */

/* The constant does not fit MOVI, so GCC loads it from a literal with L32R. */
__attribute__((noinline)) unsigned int rea_xtensa_call0_c_scale(unsigned int value,
                                                                unsigned int factor)
{
    return value + factor + 0x1234567u;
}

/* call0 passes `kept` in a2 and keeps it in a callee-saved register across the call. */
__attribute__((noinline)) unsigned int rea_xtensa_call0_c_entry(unsigned int value)
{
    unsigned int kept = value ^ 0x5au;
    return rea_xtensa_call0_c_scale(kept, 5u) + kept;
}
