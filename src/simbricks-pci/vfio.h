#ifndef GUEST_VFIO_H_
#define GUEST_VFIO_H_

#define VFIO_API_VERSION 0

int vfio_init(const char *pci_dev);
int vfio_init(const char *pci_dev, int group_id);
int vfio_map_region(int dev, int idx, void **addr, size_t *len);
int vfio_get_region_info(int dev, int i, struct vfio_region_info *reg);
int vfio_busmaster_enable(int dev);

#endif /* ndef GUEST_VFIO_H_ */
