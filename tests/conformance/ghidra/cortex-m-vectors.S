/* Freestanding, source-owned M-profile vector table. Never executed by REA. */
  .syntax unified
  .thumb

  .section .isr_vector, "a", %progbits
  .p2align 2
  .global rea_cm_vectors
rea_cm_vectors:
  .word _stack_top
  .word Reset_Handler
  .word NMI_Handler
  .word HardFault_Handler
  .word 0, 0, 0, 0, 0, 0, 0
  .word SVC_Handler
  .word 0, 0
  .word PendSV_Handler
  .word SysTick_Handler

  .text
  .p2align 1
  .global Default_Handler
  .type Default_Handler, %function
  .thumb_func
Default_Handler:
  b Default_Handler
  .size Default_Handler, . - Default_Handler

  .weak NMI_Handler
  .thumb_set NMI_Handler, Default_Handler
  .weak HardFault_Handler
  .thumb_set HardFault_Handler, Default_Handler
  .weak SVC_Handler
  .thumb_set SVC_Handler, Default_Handler
  .weak PendSV_Handler
  .thumb_set PendSV_Handler, Default_Handler
  .weak SysTick_Handler
  .thumb_set SysTick_Handler, Default_Handler

/* Base-standard builds call the AEABI helper; the fixture never runs it. */
  .global __aeabi_fadd
  .type __aeabi_fadd, %function
  .thumb_func
__aeabi_fadd:
  bx lr
  .size __aeabi_fadd, . - __aeabi_fadd
