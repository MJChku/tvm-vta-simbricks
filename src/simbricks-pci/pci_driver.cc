/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
 #include <bits/stdint-uintn.h>
 #include <bits/types/struct_timespec.h>
 #include <vta/driver.h>
 #include <cstdlib>
 #include <thread>
 #include <iostream>
 #include <time.h>
 #include <sys/types.h>
 #include <sys/stat.h>
 #include <fcntl.h>
 #include <sys/mman.h>
 #include <string.h>
 #include <stdlib.h>
 #include "pci_driver.h"

 #define BPF
 #ifdef BPF
 #include <bpf/bpf.h>
 
 void tick_nex() {
  __asm__ volatile("ud2");
}

 static int vts_fd;
 uint64_t read_vts(){
   __u64 vts = 0;
   __u32 index = 0;
   bpf_map_lookup_elem(vts_fd, &index, &vts);
   return vts;
 }
 
 void custom_sleep(volatile uint64_t sl_time){
   uint64_t time_enter = read_vts();
   uint64_t time_now = time_enter;
   while(time_now < time_enter+sl_time){
      // usleep(sl_time/1000);  
      time_now = read_vts();
   }
 //  printf("time now %ld, enter %ld, sleep for %ld\n", time_now, time_enter, sl_time);
  //flush printf 
   // fflush(stdout);
 }
 #else
 void custom_sleep(volatile uint64_t sl_time){
 return ;
 }
 #endif
 
 static void *alloc_base = nullptr;
 static size_t alloc_size = 512 * 1024 * 1024;
 static size_t alloc_off = 0;
 static uint64_t total_vta_time = 0;
 static int dev_id = -1;

uintptr_t open_shm_for_nex(const char* shm_path, int reset) {
  printf("vta driver shm_path: %s\n", shm_path);
  // Use shm_open for POSIX shared memory objects.
  int fd = shm_open(shm_path, O_RDWR, 0666);
  if (fd == -1) {
      perror("shm_open");
      exit(EXIT_FAILURE);
  }
  // Get the size of the shared memory region.
  struct stat sb;
  if (fstat(fd, &sb) == -1) {
      perror("fstat");
      close(fd);
      exit(EXIT_FAILURE);
  }
  printf("%s sb.st_size: %ld\n", shm_path, sb.st_size);
  size_t region_size = sb.st_size;
  if (region_size == 0) {
      fprintf(stderr, "Error: Shared memory region size is 0.\n");
      close(fd);
      exit(EXIT_FAILURE);
  }
  
  // Map the shared memory region into our address space.
  void *mmap_base = mmap(NULL, region_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (mmap_base == MAP_FAILED) {
      perror("mmap");
      close(fd);
      exit(EXIT_FAILURE);
  }
  if(reset){
    memset(mmap_base, 0, region_size);
  }
  printf("Memory mapped at address %p, size %zu bytes.\n", mmap_base, region_size);
  // The mapping remains valid even after closing fd.
  return (uintptr_t)mmap_base;
}


 static void alloc_init()
 {
     if (alloc_base){
       return;
     }
 
 #ifdef BPF
   vts_fd =  bpf_obj_get("/sys/fs/bpf/vts");
 #endif
   assert(vts_fd != -1);

   char *device = std::getenv("VTA_DEVICE");
   if (device == nullptr) {
      std::cerr << "VTA_DEVICE is not set" << std::endl;
      abort();
   }
   dev_id = atoi(device);

   char shm_dma_name[200];
   sprintf((char*)shm_dma_name, "vta_nex_dma_%d", dev_id);
   alloc_base = (void*)open_shm_for_nex(shm_dma_name, 1);
   
  std::cerr << "simbricks-pci: allocator initialized" << std::endl;
 }
 
 #define VTA 2
 
 uintptr_t driver_initialize(int type){

  if(dev_id == -1){
    char *device = std::getenv("VTA_DEVICE");
    if (device == nullptr) {
      std::cerr << "VTA_DEVICE is not set" << std::endl;
      abort();
    }
    dev_id = atoi(device);
  }

  printf("Simbricks-pci VTA driver init device number %d\n", dev_id);
 
 #ifdef BPF
  //  printf("Simbricks-pci VTA driver init \n");
  //  char* mmio_base_str = getenv("ACCVM_MMIO_BASE");
  //  printf("mmio str: %s\n", mmio_base_str);
  // uintptr_t ptr =  (uintptr_t)strtoul(mmio_base_str, NULL, 0)+(10*type+dev_id)*4096;
  const char *shm_path = "/nex_mmio_regions";
  uintptr_t ptr = (uintptr_t)open_shm_for_nex(shm_path, 0)+(10*type+dev_id)*4096;
  printf("Simbricks-pci mmio region mapped\n");
  return ptr;
 #else
   return 0;
 #endif
 }
 
 // control registers for the VTA, based on
 // 3rdparty/vta-hw/src/simbricks-pci/pci_driver.cc
 typedef struct __attribute__((packed)) VTARegs {
     uint32_t _0x00; // 0
     uint32_t _0x04;  // 4
     uint32_t _0x08; // 8
     union{
       uint32_t insn_phy_addr_lh; // 12
       uint32_t _0x0c; // 12
     };
     union {
       uint32_t insn_phy_addr_hh; // 16
       uint32_t _0x10; // 16
     };
     uint32_t _0x14; // 20
     uint32_t _0x18; // 24
     uint32_t _0x1c; // 28
     uint32_t _0x20; // 32
     uint64_t _0x24; // 36
     uint32_t _0x2c; // 44
 } VTARegs;
 
 static void *VTA_MMIO_BASE = NULL;
 
 void initialize_vta(void) {
   VTA_MMIO_BASE = (void *)driver_initialize(VTA);
 }
 
 //returns virtual addr
 void* VTAMemAlloc(size_t size, int cached) {
   //std::cerr << "simbricks-pci: VTAMemAlloc(" << size << ")" << std::endl;
   alloc_init();
 
   assert (alloc_off + size <= alloc_size);
   void *addr = (void *) ((uint8_t *) alloc_base + alloc_off);
   alloc_off += size;
   //std::cerr << "simbricks-pci:    = " << alloc_base << " now:"<< addr << " end:" << alloc_base + alloc_size << std::endl;
   return addr;
 }

 void VTAMemFree(void* buf) {
 }
 
 // this is fpga physical, which is fake addr to lpn 
 vta_phy_addr_t VTAMemGetPhyAddr(void* buf) {
     return ((uintptr_t) buf - (uintptr_t) alloc_base);
 }
 
 // dst is  virtual addr
 void VTAMemCopyFromHost(void* dst, const void* src, size_t size) {
   // printf("VTA Mem Copy From Host, size %lu \n", size);
   memcpy(dst, src, size);
 }
 
 // dst is  virtual addr
 void VTAMemCopyToHost(void* dst, const void* src, size_t size) {
   // printf("VTA Mem Copy To Host, size %lu \n", size);
   memcpy(dst, src, size);
 }
 
 void VTAFlushCache(void* vir_addr, vta_phy_addr_t phy_addr, int size) {
  
   // printf("VTA Flush Cache, size %lu \n", size);
 }
 
 void VTAInvalidateCache(void* vir_addr, vta_phy_addr_t phy_addr, int size) {
 
   // printf("VTA Invalidate Cache, size %lu \n", size);
 }

 void *VTAMapRegister(uint32_t addr) {
    if(VTA_MMIO_BASE == NULL){
      initialize_vta();
    }
    void* regs = VTA_MMIO_BASE;
    return (char*)regs+addr;
   
  }
  
  void VTAUnmapRegister(void *vta) {
    // Unmap memory
    // TODO
  }
  
  void VTAWriteMappedReg(void* base_addr, uint32_t offset, uint32_t val) {
    *((volatile uint32_t *) (reinterpret_cast<char *>(base_addr) + offset)) = val;
    tick_nex();
  }
  
  void VTAWriteMappedReg64(void* base_addr, uint32_t offset, uint64_t val) {
    *((volatile uint64_t *) (reinterpret_cast<char *>(base_addr) + offset)) = val;
    tick_nex();
  }

  uint32_t VTAReadMappedReg(void* base_addr, uint32_t offset) {
    volatile uint32_t* ptr = (volatile uint32_t *) (reinterpret_cast<char *>(base_addr) + offset);
    *ptr = 0xFFFFFFFF;
    tick_nex();
    return *ptr;
    // return *((volatile uint32_t *) (reinterpret_cast<char *>(base_addr) + offset));
  }

 class VTADevice {
    public:
     VTADevice() {
       // VTA stage handles
       vta_host_handle_ = VTAMapRegister(0);
     }
   
     ~VTADevice() {
       // Close VTA stage handle
       VTAUnmapRegister(vta_host_handle_);
     }
   
     int Run(vta_phy_addr_t insn_phy_addr,
             uint32_t insn_count,
             uint32_t wait_cycles) {
      VTAWriteMappedReg(vta_host_handle_, 0x08, insn_count);
      VTAWriteMappedReg(vta_host_handle_, 0x0c, insn_phy_addr);
      VTAWriteMappedReg(vta_host_handle_, 0x10, insn_phy_addr >> 32);
      VTAWriteMappedReg(vta_host_handle_, 0x14, 0);
      VTAWriteMappedReg(vta_host_handle_, 0x18, 0);
      VTAWriteMappedReg(vta_host_handle_, 0x1c, 0);
      VTAWriteMappedReg(vta_host_handle_, 0x20, 0);

      // this is for simbricks in nxsim to have base address
       VTAWriteMappedReg64(vta_host_handle_, 0x24,(uint64_t) alloc_base);
   
       // VTA start
       VTAWriteMappedReg(vta_host_handle_, 0x0, VTA_START);
   
       timespec start;
       clock_gettime(CLOCK_MONOTONIC, &start);
       // Loop until the VTA is done
       unsigned flag = 0;
       for (;;) {
         flag = VTAReadMappedReg(vta_host_handle_, 0x00);
         flag &= 0x2;
         if (flag == 0x2) break;
            // 100us
            // usleep(10);
           custom_sleep(10000);
         // std::this_thread::yield();
       }
       timespec end;
       clock_gettime(CLOCK_MONOTONIC, &end);
       total_vta_time += (end.tv_sec - start.tv_sec) * 1000000000 + (end.tv_nsec - start.tv_nsec);
       printf("total vta_time so far: %lu\n", total_vta_time);
       // Report error if timeout
       // return t < wait_cycles ? 0 : 1;
       return 0;
     }
   
    private:
     // VTA handles (register maps)
     void* vta_host_handle_{nullptr};
};
 

VTADeviceHandle VTADeviceAlloc() {
  return new VTADevice();
}

void VTADeviceFree(VTADeviceHandle handle) {
  delete static_cast<VTADevice*>(handle);
}

int VTADeviceRun(VTADeviceHandle handle,
                 vta_phy_addr_t insn_phy_addr,
                 uint32_t insn_count,
                 uint32_t wait_cycles) {
  return static_cast<VTADevice*>(handle)->Run(
      insn_phy_addr, insn_count, wait_cycles);
}
