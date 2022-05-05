MEMORY
{
    FLASH (rx) : ORIGIN = 0x00000000, LENGTH = ##WOLFBOOT_PARTITION_BOOT_ADDRESS##
    RAM (rwx) :  ORIGIN = 0x20000000, LENGTH = 64K
}

SECTIONS
{


    .text :
    {
        _start_text = .;
        KEEP(*(.isr_vector))
        *(
            EXCLUDE_FILE(*wolfcrypt*)
            .text*)
        *(EXCLUDE_FILE(*wolfcrypt*) .rodata*)
        *(.init*)
        *(.fini*)
        . = ALIGN(4);
        _end_text = .;
    } > FLASH

    .edidx :
    {
        . = ALIGN(4);
        *(.ARM.exidx*)
    } > FLASH

    _stored_data = .;

    .data : AT (_stored_data)
    {
        _start_data = .;
        KEEP(*(.data*))
        . = ALIGN(4);
        _end_data = .;
    } > RAM

    .bss (NOLOAD) : 
    {
        _start_bss = .;
        __bss_start__ = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        _end_bss = .;
        __bss_end__ = .;
        _end = .;
    } > RAM
    
    .wolfcrypt_shared :
    {
        . = ORIGIN(FLASH) + 0x2000;
        KEEP(*(EXCLUDE_FILE(src/*) .text.wc_*))
        KEEP(*(EXCLUDE_FILE(src/*) .text.*))
        KEEP(*(EXCLUDE_FILE(src/*) .rodata*))
    } > FLASH






}

END_STACK = ORIGIN(RAM) + LENGTH(RAM);
