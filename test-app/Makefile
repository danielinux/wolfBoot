TARGET?=none
ARCH?=ARM
KINETIS_CMSIS?=$(KINETIS)/CMSIS

CFLAGS:=-g -ggdb -Wall -Wstack-usage=1024 -ffreestanding -Wno-unused -DPLATFORM_$(TARGET) -I../include -nostartfiles

APP_OBJS:=app_$(TARGET).o led.o system.o timer.o ../hal/$(TARGET).o ../src/libwolfboot.o
include ../arch.mk

ifeq ($(ARCH),RISCV)
  APP_OBJS+=startup_riscv.o vector_riscv.o
endif

ifeq ($(ARCH),ARM)
  APP_OBJS+=startup_arm.o
endif

ifeq ($(V),0)
  Q=@
endif

LSCRIPT:=$(ARCH).ld
ifeq ($(TARGET),stm32f7)
  LSCRIPT=ARM-stm32f7.ld
  CFLAGS+=-DDUALBANK_SWAP
endif
LDFLAGS:=$(CFLAGS) -T $(LSCRIPT) -Wl,-gc-sections -Wl,-Map=image.map

ifeq ($(EXT_FLASH),1)
  CFLAGS+=-DEXT_FLASH=1 -DPART_UPDATE_EXT=1
endif

ifeq ($(SPI_FLASH),1)
  CFLAGS+=-DSPI_FLASH
  APP_OBJS+=../hal/spi/spi_drv_$(TARGET).o ../src/spi_flash.o
endif

ifeq ($(TARGET),kinetis)
  CFLAGS+= -I$(KINETIS_DRIVERS)/drivers -I$(KINETIS_DRIVERS) -DCPU_$(KINETIS_CPU) -I$(KINETIS_CMSIS)/Include -DDEBUG_CONSOLE_ASSERT_DISABLE=1 -DNVM_FLASH_WRITEONCE=1
  APP_OBJS+= $(KINETIS_DRIVERS)/drivers/fsl_clock.o $(KINETIS_DRIVERS)/drivers/fsl_ftfx_flash.o $(KINETIS_DRIVERS)/drivers/fsl_ftfx_cache.o \
		 $(KINETIS_DRIVERS)/drivers/fsl_ftfx_controller.o $(KINETIS_DRIVERS)/drivers/fsl_gpio.o
endif

ifeq ($(TARGET),stm32g0)
  CFLAGS+=-DNVM_FLASH_WRITEONCE=1
endif

ifeq ($(TARGET),hifive1.freedom)
  CFLAGS+=-I$(FREEDOM_E_SDK)/freedom-metal/ -D__METAL_MACHINE_HEADER=\"$(FREEDOM_E_SDK)/bsp/sifive-hifive1/metal.h\"
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/clock.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/led.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/cache.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/cpu.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/gpio.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/interrupt.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/uart.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/tty.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/spi.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/shutdown.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/timer.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/drivers/sifive,fe310-g000,hfrosc.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/drivers/sifive,fe310-g000,hfxosc.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/drivers/sifive,fe310-g000,pll.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/drivers/sifive,fe310-g000,prci.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/drivers/sifive,spi0.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/drivers/sifive,uart0.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/drivers/sifive,global-external-interrupts0.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/drivers/sifive,local-external-interrupts0.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/drivers/sifive,gpio0.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/drivers/sifive,gpio-leds.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/drivers/riscv,clint0.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/drivers/riscv,plic0.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/drivers/riscv,cpu.o
  APP_OBJS+=$(FREEDOM_E_SDK)/freedom-metal/src/drivers/fixed-clock.o
endif

ifeq ($(TARGET),hifive1)
  CFLAGS+=-DRAMFUNCTION='__attribute__((used,section(".ramcode")))'
  APP_OBJS+=hifive1_write_page.o
endif

standalone:CFLAGS+=-DTEST_APP_STANDALONE
standalone:LDFLAGS:=$(CFLAGS) -T standalone.ld -Wl,-gc-sections -Wl,-Map=image.map

image.bin: image.elf
	@echo "\t[BIN] $@"
	$(Q)$(OBJCOPY) -O binary $^ $@

image.elf: $(APP_OBJS) $(LSCRIPT)
	@echo "\t[LD] $@"
	$(Q)$(LD) $(LDFLAGS) $(APP_OBJS) -o $@


standalone: image.bin

%.o:%.c
	@echo "\t[CC-$(ARCH)] $@"
	$(Q)$(CC) $(CFLAGS) -c -o $@ $^

%.o:%.S
	@echo "\t[AS-$(ARCH)] $@"
	$(Q)$(CC) $(CFLAGS) -c -o $@ $^

clean:
	@rm -f *.bin *.elf tags *.o
